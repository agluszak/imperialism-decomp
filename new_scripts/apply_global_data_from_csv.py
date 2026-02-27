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
  .venv/bin/python new_scripts/apply_global_data_from_csv.py <csv_path> [--apply]
"""

from __future__ import annotations

import argparse
import csv
import re
from functools import lru_cache
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


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


@lru_cache(maxsize=1024)
def resolve_named_data_type(dtm, base_name: str):
    target = base_name.strip()
    if not target:
        return None
    best = None
    best_score = None
    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        try:
            if dt.getName() != target:
                continue
            cat = str(dt.getCategoryPath().getPath())
            if cat in (
                "/imperialism/classes",
                "/Imperialism/classes",
                "/imperialism/types",
                "/Imperialism/types",
            ):
                pri = 0
            elif cat == "/":
                pri = 1
            else:
                pri = 2
            score = (pri, len(cat), cat)
            if best is None or score < best_score:
                best = dt
                best_score = score
        except Exception:
            continue
    return best


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
        dt = dtm.getDataType(path)
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
        dt = resolve_named_data_type(dtm, base)
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
        default=str(Path(__file__).resolve().parents[1]),
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

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
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
