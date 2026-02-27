#!/usr/bin/env python3
"""
Create minimal class struct datatypes from CSV.

CSV columns:
  - type_name (required)
  - size (optional, default: 0x4)

Each created/updated struct is seeded with:
  - offset 0x0: void* pVtable

Usage:
  uv run impk create_minimal_class_structs_from_csv \
    --csv tmp_decomp/runtime_state_classes.csv --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_int_default

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Input CSV with type_name,size")
    ap.add_argument("--category", default="/imperialism/classes", help="Datatype category")
    ap.add_argument("--default-size", default="0x4", help="Default struct size")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = root / csv_path
    if not csv_path.exists():
        print(f"[error] missing csv: {csv_path}")
        return 1

    default_size = parse_int_default(args.default_size, default=0)
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
        sz = parse_int_default(r.get("size"), default=default_size)
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

    with open_program(root) as program:
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
