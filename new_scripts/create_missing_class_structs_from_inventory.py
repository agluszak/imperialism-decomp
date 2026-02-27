#!/usr/bin/env python3
"""
Create minimal class structs for classes missing datatype definitions.

Input:
  CSV from build_class_model_inventory.py (default: tmp_decomp/class_model_inventory.csv)

Selection gates (conservative):
  - class_name starts with 'T'
  - has_struct_type == 0
  - has at least one anchor: class_desc or vtbl or typename symbol
  - optional minimum methods in class namespace

Created datatype shape:
  struct <ClassName> { void* pVtable; }

Usage:
  .venv/bin/python new_scripts/create_missing_class_structs_from_inventory.py
  .venv/bin/python new_scripts/create_missing_class_structs_from_inventory.py --apply
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


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def i(text: str | None) -> int:
    try:
        return int((text or "").strip() or "0")
    except Exception:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--inventory-csv",
        default="tmp_decomp/class_model_inventory.csv",
        help="CSV produced by build_class_model_inventory.py",
    )
    ap.add_argument(
        "--category",
        default="/imperialism/classes",
        help="Datatype category path",
    )
    ap.add_argument(
        "--min-methods",
        type=int,
        default=1,
        help="Require at least this many methods in class namespace",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional max number of classes to process (0 = no limit)",
    )
    ap.add_argument("--apply", action="store_true", help="Apply datatype creation")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    inv = Path(args.inventory_csv)
    if not inv.is_absolute():
        inv = root / inv
    if not inv.exists():
        print(f"[error] missing inventory csv: {inv}")
        return 1

    rows = list(csv.DictReader(inv.open("r", encoding="utf-8")))
    selected: list[dict[str, str]] = []
    for r in rows:
        cls = (r.get("class_name") or "").strip()
        if not cls.startswith("T"):
            continue
        if i(r.get("has_struct_type")) != 0:
            continue
        if i(r.get("method_count_in_namespace")) < args.min_methods:
            continue
        has_anchor = (
            i(r.get("has_class_desc_symbol")) == 1
            or i(r.get("has_vtbl_symbol")) == 1
            or i(r.get("has_typename_symbol")) == 1
        )
        if not has_anchor:
            continue
        selected.append(r)

    selected.sort(
        key=lambda r: (
            -i(r.get("method_count_in_namespace")),
            -(i(r.get("has_vtbl_symbol")) + i(r.get("has_class_desc_symbol"))),
            r.get("class_name") or "",
        )
    )
    if args.limit > 0:
        selected = selected[: args.limit]

    print(
        f"[plan] selected={len(selected)} min_methods={args.min_methods} "
        f"limit={args.limit} apply={args.apply}"
    )
    for r in selected[:200]:
        print(
            f"  {r.get('class_name')} methods={r.get('method_count_in_namespace')} "
            f"desc={r.get('has_class_desc_symbol')} vtbl={r.get('has_vtbl_symbol')} "
            f"tname={r.get('has_typename_symbol')}"
        )
    if len(selected) > 200:
        print(f"  ... ({len(selected) - 200} more)")

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

        tx = program.startTransaction("Create missing class structs from inventory")
        created = skipped_existing = failed = 0
        try:
            for r in selected:
                cls = (r.get("class_name") or "").strip()
                if not cls:
                    continue
                existing = dtm.getDataType(cat, cls)
                if existing is not None:
                    skipped_existing += 1
                    continue
                try:
                    st = StructureDataType(cat, cls, 4)
                    st.replaceAtOffset(0, p_void, 4, "pVtable", "auto: minimal class seed")
                    dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
                    created += 1
                except Exception as ex:
                    failed += 1
                    print(f"[fail] {cls} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("create missing class structs from inventory", None)
        print(
            f"[done] created={created} skipped_existing={skipped_existing} "
            f"failed={failed} selected={len(selected)}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
