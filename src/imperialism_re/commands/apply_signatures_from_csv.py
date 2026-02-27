#!/usr/bin/env python3
"""
Apply function signatures from CSV.

CSV columns:
  - address (required)
  - calling_convention (optional, e.g. __thiscall, __cdecl, __fastcall)
  - return_type (required, e.g. void, void*, byte, int, uint, bool)
  - params (optional): semicolon-separated name:type pairs
      Example: pThis:void*;freeSelfFlag:byte

Usage:
  uv run impk apply_signatures_from_csv <csv_path> [--apply] [--project-root PATH]
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import find_named_data_type, resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex


def split_pointer_type(type_name: str) -> tuple[str, int]:
    t = type_name.strip().replace(" ", "")
    stars = 0
    while t.endswith("*"):
        stars += 1
        t = t[:-1]
    return t, stars


def normalize_base_type_name(name: str) -> str:
    t = name.strip()
    # Strip common C/C++ modifiers/keywords used in CSV prototypes.
    t = t.replace("const ", "").replace("volatile ", "")
    t = t.replace("struct ", "").replace("class ", "")
    return t.strip()


def _looks_like_enum_name(base_name: str) -> bool:
    return bool(re.match(r"^E[A-Za-z0-9_]+$", base_name))


def build_data_type(type_name: str, dtm, unresolved_enum_refs: set[str] | None = None):
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
    base_name = normalize_base_type_name(base_name)
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
    }

    dt = base_map.get(base_key)
    if dt is None:
        if "/" in base_name:
            dt = resolve_datatype_by_path_or_legacy_aliases(dtm, base_name)
        else:
            dt = find_named_data_type(dtm, base_name)

    if dt is None and unresolved_enum_refs is not None:
        if "/" in base_name or _looks_like_enum_name(base_name):
            unresolved_enum_refs.add(base_name)

    if dt is None:
        # Fallback for unknown type names keeps operation safe.
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
    ap.add_argument("csv_path", help="CSV with signature rows")
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
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        planned = []
        bad_rows = 0
        unresolved_enum_refs: set[str] = set()
        for i, row in enumerate(rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            ret_txt = (row.get("return_type") or "").strip()
            cc_txt = (row.get("calling_convention") or "").strip()
            params_txt = row.get("params") or ""
            if not addr_txt or not ret_txt:
                bad_rows += 1
                print(f"[row-fail] row={i} missing address/return_type")
                continue
            try:
                addr_int = parse_hex(addr_txt)
                ret_dt = build_data_type(ret_txt, dtm, unresolved_enum_refs)
                params = parse_params(params_txt)
                params_types = [(pn, pt, build_data_type(pt, dtm, unresolved_enum_refs)) for pn, pt in params]
            except Exception as ex:
                bad_rows += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue
            planned.append((addr_int, cc_txt, ret_dt, params, params_types))

        print(f"[rows] total={len(rows)} planned={len(planned)} bad_rows={bad_rows}")
        if unresolved_enum_refs:
            print("[warn] unresolved enum type references (fallback type used):")
            for ref in sorted(unresolved_enum_refs):
                print(f"  - {ref}")

        preview = 0
        for addr_int, cc_txt, ret_dt, params, _params_types in planned:
            addr = af.getAddress(f"0x{addr_int:08x}")
            f = fm.getFunctionAt(addr)
            if f is None:
                print(f"  [miss] 0x{addr_int:08x}")
                continue
            ptxt = ", ".join(f"{n}:{t}" for n, t in params) if params else "<none>"
            cc_show = cc_txt if cc_txt else "<unchanged>"
            print(f"  0x{addr_int:08x} {f.getName()} :: cc={cc_show} ret={ret_dt.getName()} params={ptxt}")
            preview += 1
            if preview >= 200:
                break

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply signatures from CSV")
        ok = 0
        skip = 0
        fail = 0
        try:
            for addr_int, cc_txt, ret_dt, _params, params_types in planned:
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

                    p_objs = [
                        ParameterImpl(nm, pdt, program, SourceType.USER_DEFINED)
                        for nm, _ptxt, pdt in params_types
                    ]
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        p_objs,
                    )
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

        program.save("apply signatures from csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
