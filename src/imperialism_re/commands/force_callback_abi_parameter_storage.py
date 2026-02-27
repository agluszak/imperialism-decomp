#!/usr/bin/env python3
"""
Force custom parameter storage for callback-ABI functions.

These are functions where the return-address slot (Stack[0x00]) is actually
a callback context value pushed by the caller.  Ghidra's standard parameter-ID
cannot model this, so the decompiler emits ``unaff_retaddr``.

This command overrides each listed function with CUSTOM_STORAGE parameters
whose stack offsets are given explicitly, including offset 0x00 for the
reinterpreted return-address slot.

CSV columns:
  - address (required)  – function entry point
  - calling_convention  – e.g. __thiscall, __stdcall
  - return_type         – e.g. void, int
  - params_with_storage – semicolon-separated entries of the form
        name:type:storage
    where *storage* is one of:
        stack@<hex_offset>    – explicit stack slot  (e.g. stack@0x00)
        ecx                   – ECX register (for this-pointer)

Usage:
  uv run impk force_callback_abi_parameter_storage <csv> [--apply]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex
from imperialism_re.core.wave_shared import build_data_type


def parse_params_with_storage(raw: str):
    """Parse ``name:type:storage;...`` into list of (name, type_str, storage_spec)."""
    out: list[tuple[str, str, str]] = []
    txt = (raw or "").strip()
    if not txt:
        return out
    for part in txt.split(";"):
        p = part.strip()
        if not p:
            continue
        pieces = p.split(":", 2)
        if len(pieces) != 3:
            raise ValueError(f"expected name:type:storage, got: {p}")
        name, typ, storage = (x.strip() for x in pieces)
        if not name or not typ or not storage:
            raise ValueError(f"empty field in: {p}")
        out.append((name, typ, storage))
    return out


def make_variable_storage(program, storage_spec: str, size: int):
    """Build a Ghidra VariableStorage from a spec string."""
    from ghidra.program.model.listing import VariableStorage as VS

    spec = storage_spec.strip().lower()

    if spec.startswith("stack@"):
        offset_str = spec[len("stack@"):]
        offset = parse_hex(offset_str)
        stack_space = program.getAddressFactory().getStackSpace()
        addr = stack_space.getAddress(offset)
        return VS(program, addr, size)

    if spec == "ecx":
        from ghidra.program.model.lang import Register
        reg = program.getLanguage().getRegister("ECX")
        return VS(program, reg)

    raise ValueError(f"unsupported storage spec: {storage_spec}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path", help="CSV with custom-storage signature rows")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    if not csv_path.exists():
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("no rows")
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.listing import (
            Function,
            ParameterImpl,
        )
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        planned = []
        bad_rows = 0
        for i, row in enumerate(rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            ret_txt = (row.get("return_type") or "").strip()
            cc_txt = (row.get("calling_convention") or "").strip()
            params_txt = row.get("params_with_storage") or ""
            if not addr_txt or not ret_txt:
                bad_rows += 1
                print(f"[row-fail] row={i} missing address/return_type")
                continue
            try:
                addr_int = parse_hex(addr_txt)
                ret_dt = build_data_type(ret_txt, dtm)
                params = parse_params_with_storage(params_txt)
            except Exception as ex:
                bad_rows += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue
            planned.append((addr_int, cc_txt, ret_dt, params))

        print(f"[rows] total={len(rows)} planned={len(planned)} bad_rows={bad_rows}")

        for addr_int, cc_txt, ret_dt, params in planned:
            addr = af.getAddress(f"0x{addr_int:08x}")
            f = fm.getFunctionAt(addr)
            if f is None:
                print(f"  [miss] 0x{addr_int:08x}")
                continue
            ptxt = ", ".join(f"{n}:{t}@{s}" for n, t, s in params) if params else "<none>"
            cc_show = cc_txt if cc_txt else "<unchanged>"
            print(f"  0x{addr_int:08x} {f.getName()} :: cc={cc_show} ret={ret_dt.getName()} params=[{ptxt}]")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Force callback ABI parameter storage")
        ok = 0
        fail = 0
        try:
            for addr_int, cc_txt, ret_dt, params in planned:
                addr = af.getAddress(f"0x{addr_int:08x}")
                f = fm.getFunctionAt(addr)
                if f is None:
                    fail += 1
                    print(f"[miss] no function at 0x{addr_int:08x}")
                    continue
                try:
                    old_sig = str(f.getSignature())

                    if cc_txt:
                        f.setCallingConvention(cc_txt)

                    f.setCustomVariableStorage(True)

                    p_objs = []
                    for name, type_str, storage_spec in params:
                        dt = build_data_type(type_str, dtm)
                        size = dt.getLength()
                        if size <= 0:
                            size = 4  # default pointer/int size
                        vs = make_variable_storage(program, storage_spec, size)
                        p = ParameterImpl(name, dt, vs, program)
                        p_objs.append(p)

                    f.replaceParameters(
                        Function.FunctionUpdateType.CUSTOM_STORAGE,
                        True,
                        SourceType.USER_DEFINED,
                        p_objs,
                    )
                    f.setReturnType(ret_dt, SourceType.USER_DEFINED)

                    new_sig = str(f.getSignature())
                    ok += 1
                    print(f"[ok] 0x{addr_int:08x} {f.getName()}")
                    print(f"     old: {old_sig}")
                    print(f"     new: {new_sig}")
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{addr_int:08x} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("force callback ABI parameter storage", None)
        print(f"[done] ok={ok} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
