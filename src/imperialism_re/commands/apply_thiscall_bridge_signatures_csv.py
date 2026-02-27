#!/usr/bin/env python3
"""
Apply targeted bridge-style signatures from CSV, preserving explicit `this` for __thiscall.

CSV columns:
  - address (required)
  - calling_convention (optional, default: __thiscall)
  - return_type (required)
  - params (optional): semicolon-separated name:type pairs (post-this parameters)
  - this_type (optional, default: keep existing first param type if present, else void*)

For __thiscall rows:
  - ensure explicit first parameter named `this`
  - keep existing first-param datatype when possible (unless this_type provided)
  - append CSV params after `this`
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def split_pointer_type(type_name: str) -> tuple[str, int]:
    t = type_name.strip().replace(" ", "")
    stars = 0
    while t.endswith("*"):
        stars += 1
        t = t[:-1]
    return t, stars

def build_data_type(type_name: str):
    from ghidra.program.model.data import (
        BooleanDataType,
        ByteDataType,
        CharDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    base_name, ptr_depth = split_pointer_type(type_name)
    base_key = base_name.lower()
    base_map = {
        "void": VoidDataType.dataType,
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "bool": BooleanDataType.dataType,
        "undefined1": ByteDataType.dataType,
        "undefined2": UnsignedShortDataType.dataType,
        "undefined4": IntegerDataType.dataType,
        "undefined": IntegerDataType.dataType,
    }
    dt = base_map.get(base_key)
    if dt is None:
        dt = VoidDataType.dataType if ptr_depth > 0 else IntegerDataType.dataType
    for _ in range(ptr_depth):
        dt = PointerDataType(dt)
    return dt

def parse_params(raw: str):
    out: list[tuple[str, str]] = []
    txt = (raw or "").strip()
    if not txt:
        return out
    for part in txt.split(";"):
        p = part.strip()
        if not p:
            continue
        if ":" not in p:
            raise ValueError(f"invalid param entry (expected name:type): {p}")
        name, typ = p.split(":", 1)
        name = name.strip()
        typ = typ.strip()
        if not name or not typ:
            raise ValueError(f"invalid param entry (empty name/type): {p}")
        out.append((name, typ))
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    if not csv_path.exists():
        print(f"[error] missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("no rows")
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        planned = []
        bad = 0
        for i, row in enumerate(rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            ret_txt = (row.get("return_type") or "").strip()
            cc_txt = (row.get("calling_convention") or "__thiscall").strip()
            params_txt = row.get("params") or ""
            this_type = (row.get("this_type") or "").strip()
            if not addr_txt or not ret_txt:
                bad += 1
                print(f"[row-fail] row={i} missing address/return_type")
                continue
            try:
                addr_i = parse_hex(addr_txt)
                ret_dt = build_data_type(ret_txt)
                params = parse_params(params_txt)
            except Exception as ex:
                bad += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue
            planned.append((addr_i, cc_txt, ret_dt, params, this_type))

        print(f"[rows] total={len(rows)} planned={len(planned)} bad={bad}")
        for addr_i, cc_txt, ret_dt, params, this_type in planned[:220]:
            addr = af.getAddress(f"0x{addr_i:08x}")
            fn = fm.getFunctionAt(addr)
            if fn is None:
                print(f"  [miss] 0x{addr_i:08x}")
                continue
            ptxt = ", ".join(f"{n}:{t}" for n, t in params) if params else "<none>"
            tt = this_type if this_type else "<auto>"
            print(
                f"  0x{addr_i:08x} {fn.getName()} cc={cc_txt} ret={ret_dt.getName()} "
                f"this={tt} post_this={ptxt}"
            )

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply thiscall bridge signatures from CSV")
        ok = skip = fail = 0
        try:
            for addr_i, cc_txt, ret_dt, params, this_type in planned:
                fn = fm.getFunctionAt(af.getAddress(f"0x{addr_i:08x}"))
                if fn is None:
                    fail += 1
                    print(f"[miss] no function at 0x{addr_i:08x}")
                    continue
                try:
                    old_sig = str(fn.getSignature())
                    fn.setCallingConvention(cc_txt)

                    new_params = []
                    if cc_txt == "__thiscall":
                        cur = list(fn.getParameters())
                        if this_type:
                            this_dt = build_data_type(this_type)
                        elif cur:
                            this_dt = cur[0].getDataType()
                        else:
                            this_dt = build_data_type("void*")
                        new_params.append(
                            ParameterImpl("this", this_dt, program, SourceType.USER_DEFINED)
                        )
                        for nm, tp in params:
                            new_params.append(
                                ParameterImpl(nm, build_data_type(tp), program, SourceType.USER_DEFINED)
                            )
                    else:
                        for nm, tp in params:
                            new_params.append(
                                ParameterImpl(nm, build_data_type(tp), program, SourceType.USER_DEFINED)
                            )

                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
                    new_sig = str(fn.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{addr_i:08x} {fn.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply thiscall bridge signatures from csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

