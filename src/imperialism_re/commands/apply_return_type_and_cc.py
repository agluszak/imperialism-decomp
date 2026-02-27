#!/usr/bin/env python3
"""
Apply return type and calling convention WITHOUT touching parameters.

This is a minimal writer command designed for functions with ``cc=unknown``
and ``undefined`` return type.  It only calls ``setCallingConvention`` and
``setReturnType``; parameters are left untouched so that Ghidra's parameter-ID
analysis fills them in naturally.

CSV columns:
  - address (required)
  - calling_convention (required, e.g. __thiscall, __cdecl, __fastcall, __stdcall)
  - return_type (required, e.g. void, int, uint, bool, void*, byte)

Usage:
  uv run impk apply_return_type_and_cc \
    tmp_decomp/inferred_batch.csv --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex


def _build_data_type(type_name: str, dtm):
    """Resolve a type name to a Ghidra DataType (simplified version)."""
    from ghidra.program.model.data import (
        BooleanDataType,
        ByteDataType,
        CharDataType,
        FloatDataType,
        DoubleDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    t = type_name.strip()
    ptr_depth = 0
    while t.endswith("*"):
        ptr_depth += 1
        t = t[:-1].rstrip()

    base_map = {
        "void": VoidDataType.dataType,
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "bool": BooleanDataType.dataType,
        "float": FloatDataType.dataType,
        "double": DoubleDataType.dataType,
        "float10": FloatDataType.dataType,  # x87 80-bit → float
    }

    dt = base_map.get(t.lower())
    if dt is None:
        from imperialism_re.core.datatypes import find_named_data_type
        dt = find_named_data_type(dtm, t)
    if dt is None:
        dt = VoidDataType.dataType if ptr_depth > 0 else IntegerDataType.dataType

    for _ in range(ptr_depth):
        dt = PointerDataType(dt)
    return dt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path", help="CSV with return_type + calling_convention rows")
    ap.add_argument("--apply", action="store_true", help="Write changes")
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
        print("[done] no rows")
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        plans = []
        bad = 0
        for i, row in enumerate(rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            cc_txt = (row.get("calling_convention") or "").strip()
            ret_txt = (row.get("return_type") or "").strip()
            if not addr_txt or not ret_txt or not cc_txt:
                bad += 1
                continue
            try:
                addr_int = parse_hex(addr_txt)
                ret_dt = _build_data_type(ret_txt, dtm)
            except Exception as ex:
                bad += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue
            plans.append((addr_int, cc_txt, ret_dt, ret_txt))

        print(f"[rows] total={len(rows)} planned={len(plans)} bad={bad}")

        # Preview
        preview = 0
        for addr_int, cc_txt, ret_dt, ret_txt in plans:
            addr = af.getAddress(f"0x{addr_int:08x}")
            f = fm.getFunctionAt(addr)
            if f is None:
                continue
            cur_cc = f.getCallingConventionName()
            cur_ret = f.getReturnType().getName()
            print(f"  0x{addr_int:08x} {f.getName()} :: {cur_cc}/{cur_ret} -> {cc_txt}/{ret_txt}")
            preview += 1
            if preview >= 20:
                if len(plans) > 20:
                    print(f"  ... ({len(plans) - 20} more)")
                break

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply return type and calling convention")
        ok = skip = fail = miss = 0
        try:
            for addr_int, cc_txt, ret_dt, ret_txt in plans:
                addr = af.getAddress(f"0x{addr_int:08x}")
                f = fm.getFunctionAt(addr)
                if f is None:
                    miss += 1
                    continue
                try:
                    old_sig = str(f.getSignature())
                    f.setCallingConvention(cc_txt)
                    f.setReturnType(ret_dt, SourceType.USER_DEFINED)
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{addr_int:08x} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply return type and cc", None)
        print(f"[done] ok={ok} skip={skip} fail={fail} miss={miss}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
