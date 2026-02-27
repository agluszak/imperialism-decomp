#!/usr/bin/env python3
"""
Create minimal class struct datatypes from CSV.

CSV columns:
  - type_name (required)
  - size (optional, default: 0x4)

Each created/updated struct is seeded with:
  - offset 0x0: void* pVtable

Usage:
  .venv/bin/python new_scripts/create_minimal_class_structs_from_csv.py \
    --csv tmp_decomp/runtime_state_classes.csv --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_int(text: str) -> int:
    t = (text or "").strip().lower()
    if not t:
        return 0
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Input CSV with type_name,size")
    ap.add_argument("--category", default="/imperialism/classes", help="Datatype category")
    ap.add_argument("--default-size", default="0x4", help="Default struct size")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = root / csv_path
    if not csv_path.exists():
        print(f"[error] missing csv: {csv_path}")
        return 1

    default_size = parse_int(args.default_size)
    if default_size <= 0:
        default_size = 4

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    plans: list[tuple[str, int]] = []
    seen = set()
    for r in rows:
        name = (r.get("type_name") or "").strip()
        if not name:
            continue
        if name in seen:
            continue
        seen.add(name)
        sz = parse_int(r.get("size") or "") if (r.get("size") or "").strip() else default_size
        if sz < 4:
            sz = 4
        plans.append((name, sz))

    plans.sort(key=lambda x: x[0].lower())
    print(f"[plan] classes={len(plans)} apply={args.apply} category={args.category}")
    for name, sz in plans[:200]:
        print(f"  {name} size=0x{sz:x}")
    if len(plans) > 200:
        print(f"  ... ({len(plans) - 200} more)")

    if not args.apply:
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            PointerDataType,
            StructureDataType,
            VoidDataType,
        )

        dtm = program.getDataTypeManager()
        cat = CategoryPath(args.category)
        p_void = PointerDataType(VoidDataType.dataType)

        tx = program.startTransaction("Create minimal class structs from CSV")
        created = updated = failed = 0
        try:
            for name, sz in plans:
                try:
                    st = StructureDataType(cat, name, sz)
                    st.replaceAtOffset(0, p_void, 4, "pVtable", "auto minimal class seed")
                    before = dtm.getDataType(cat, name)
                    dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
                    if before is None:
                        created += 1
                    else:
                        updated += 1
                except Exception as ex:
                    failed += 1
                    print(f"[fail] {name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("create minimal class structs from csv", None)
        print(f"[done] created={created} updated={updated} failed={failed}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

