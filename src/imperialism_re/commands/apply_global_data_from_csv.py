#!/usr/bin/env python3
"""
Batch-apply global labels/types/comments from CSV.

CSV columns:
  - address (required)
  - new_name (optional)
  - type (optional)
      builtin: byte, char, short, ushort, int, uint, void*
      struct by path: struct:/imperialism/runtime/TUiResourcePoolState
  - comment (optional)

Usage:
  uv run impk apply_global_data_from_csv <csv_path> [--apply]
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

def split_ptr(type_name: str) -> tuple[str, int]:
    t = type_name.replace(" ", "").strip()
    stars = 0
    while t.endswith("*"):
        t = t[:-1]
        stars += 1
    return t, stars

def parse_array_suffix(type_name: str) -> tuple[str, int]:
    t = type_name.strip()
    m = re.fullmatch(r"(.+)\[(\d+)\]", t)
    if not m:
        return t, 0
    base = m.group(1).strip()
    count = int(m.group(2))
    if count <= 0:
        raise ValueError(f"invalid array length: {count}")
    return base, count

def resolve_data_type(program, type_name: str):
    from ghidra.program.model.data import (
        ArrayDataType,
        ByteDataType,
        CharDataType,
        DWordDataType,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    dtm = program.getDataTypeManager()
    raw = (type_name or "").strip()
    if not raw:
        return None

    raw, arr_len = parse_array_suffix(raw)

    # Struct/type by full path.
    low = raw.lower()
    if low.startswith("struct:") or low.startswith("type:"):
        path = raw.split(":", 1)[1].strip()
        if not path:
            raise ValueError("empty struct/type path")
        dt = resolve_datatype_by_path_or_legacy_aliases(dtm, path)
        if dt is None:
            raise ValueError(f"type not found: {path}")
        return dt

    base, ptr_depth = split_ptr(raw)
    base_low = base.lower()

    base_map = {
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "dword": DWordDataType.dataType,
        "float": FloatDataType.dataType,
        "double": DoubleDataType.dataType,
        "void": VoidDataType.dataType,
    }
    dt = base_map.get(base_low)
    if dt is None:
        dt = find_named_data_type(dtm, base)
    if dt is None:
        raise ValueError(f"unsupported type: {raw}")

    for _ in range(ptr_depth):
        dt = PointerDataType(dt)
    if arr_len:
        dt = ArrayDataType(dt, arr_len, dt.getLength())
    return dt

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
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("no rows")
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        st = program.getSymbolTable()
        listing = program.getListing()

        planned = []
        bad = 0
        for i, row in enumerate(rows, start=1):
            addr_txt = (row.get("address") or "").strip()
            name = (row.get("new_name") or "").strip()
            type_txt = (row.get("type") or "").strip()
            cmt = (row.get("comment") or "").strip()
            if not addr_txt:
                bad += 1
                print(f"[row-fail] row={i} missing address")
                continue
            try:
                addr_int = parse_hex(addr_txt)
                dt = resolve_data_type(program, type_txt) if type_txt else None
            except Exception as ex:
                bad += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue
            planned.append((addr_int, name, dt, cmt))

        print(f"[rows] total={len(rows)} planned={len(planned)} bad={bad}")
        for addr_int, name, dt, cmt in planned[:200]:
            t = dt.getName() if dt is not None else "<unchanged>"
            n = name if name else "<unchanged>"
            print(f"  0x{addr_int:08x} name={n} type={t} cmt={'yes' if cmt else 'no'}")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply global data from CSV")
        ok = skip = fail = 0
        try:
            for addr_int, name, dt, cmt in planned:
                try:
                    addr = af.getAddress(f"0x{addr_int:08x}")
                    changed = False

                    if dt is not None:
                        end = addr.add(dt.getLength() - 1)
                        listing.clearCodeUnits(addr, end, False)
                        listing.createData(addr, dt)
                        changed = True

                    if name:
                        ps = st.getPrimarySymbol(addr)
                        if ps is None:
                            sym = st.createLabel(addr, name, SourceType.USER_DEFINED)
                            sym.setPrimary()
                            changed = True
                        elif ps.getName() != name:
                            ps.setName(name, SourceType.USER_DEFINED)
                            changed = True

                    if cmt:
                        cu = listing.getCodeUnitAt(addr)
                        if cu is not None:
                            cur = cu.getComment(cu.EOL_COMMENT)
                            if cur != cmt:
                                cu.setComment(cu.EOL_COMMENT, cmt)
                                changed = True

                    if changed:
                        ok += 1
                    else:
                        skip += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{addr_int:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply global data from csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
