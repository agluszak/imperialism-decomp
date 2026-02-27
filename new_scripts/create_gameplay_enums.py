#!/usr/bin/env python3
"""
Create/update core gameplay enums and optionally type key tactical tables.

Usage:
  .venv/bin/python new_scripts/create_gameplay_enums.py [--apply-tactical-tables]
"""

from __future__ import annotations

import argparse
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--apply-tactical-tables",
        action="store_true",
        help="Apply enum array types to tactical class/category slot tables",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import (
            ArrayDataType,
            CategoryPath,
            DataTypeConflictHandler,
            EnumDataType,
        )
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        cat = CategoryPath("/Imperialism")
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        enum_specs = [
            (
                "EHexDirection",
                2,
                [
                    ("HEX_DIR_0", 0),
                    ("HEX_DIR_1", 1),
                    ("HEX_DIR_2", 2),
                    ("HEX_DIR_3", 3),
                    ("HEX_DIR_4", 4),
                    ("HEX_DIR_5", 5),
                ],
            ),
            (
                "EHexDirectionMask",
                2,
                [
                    ("HEX_DIR_MASK_0", 1),
                    ("HEX_DIR_MASK_1", 2),
                    ("HEX_DIR_MASK_2", 4),
                    ("HEX_DIR_MASK_3", 8),
                    ("HEX_DIR_MASK_4", 16),
                    ("HEX_DIR_MASK_5", 32),
                ],
            ),
            (
                "ETacticalUnitActionClass",
                2,
                [
                    ("TACTICAL_ACTION_CLASS_0", 0),
                    ("TACTICAL_ACTION_CLASS_1", 1),
                    ("TACTICAL_ACTION_CLASS_2_ARTILLERY", 2),
                    ("TACTICAL_ACTION_CLASS_3", 3),
                    ("TACTICAL_ACTION_CLASS_4", 4),
                ],
            ),
            (
                "ETacticalUnitCategoryCode",
                2,
                [
                    ("TACTICAL_CATEGORY_0", 0),
                    ("TACTICAL_CATEGORY_1", 1),
                    ("TACTICAL_CATEGORY_2", 2),
                    ("TACTICAL_CATEGORY_3", 3),
                    ("TACTICAL_CATEGORY_4", 4),
                    ("TACTICAL_CATEGORY_5", 5),
                    ("TACTICAL_CATEGORY_6", 6),
                    ("TACTICAL_CATEGORY_7", 7),
                    ("TACTICAL_CATEGORY_8", 8),
                ],
            ),
        ]

        tx = program.startTransaction("Create gameplay enums")
        try:
            for name, size, values in enum_specs:
                e = EnumDataType(cat, name, size)
                for n, v in values:
                    e.add(n, v)
                dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
                print(f"[enum] {name} size={size} values={len(values)}")
        finally:
            program.endTransaction(tx, True)

        if args.apply_tactical_tables:
            table_specs = [
                (
                    "0x006693b8",
                    "/Imperialism/ETacticalUnitActionClass",
                    27,
                    "g_aeTacticalUnitActionClassBySlot",
                ),
                (
                    "0x00695528",
                    "/Imperialism/ETacticalUnitCategoryCode",
                    27,
                    "g_aeTacticalUnitCategoryBySlot",
                ),
            ]

            tx2 = program.startTransaction("Apply tactical enum tables")
            try:
                for addr_s, enum_path, count, label in table_specs:
                    addr = af.getAddress(addr_s)
                    enum_dt = dtm.getDataType(enum_path)
                    if enum_dt is None:
                        print(f"[warn] missing enum {enum_path}")
                        continue
                    arr = ArrayDataType(enum_dt, count, enum_dt.getLength())
                    end = addr.add(arr.getLength() - 1)
                    listing.clearCodeUnits(addr, end, False)
                    listing.createData(addr, arr)
                    syms = list(st.getSymbols(addr))
                    if not any(s.getName() == label for s in syms):
                        sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                        sym.setPrimary()
                    print(f"[table] {label} {addr_s} dtype={arr.getName()}")
            finally:
                program.endTransaction(tx2, True)

        program.save("create gameplay enums", None)
        print("[done]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
