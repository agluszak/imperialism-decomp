#!/usr/bin/env python3
"""
Create arrow split-command enum used by 0x64/0x65 dispatch handlers.

Creates:
  /Imperialism/EArrowSplitCommandId (size 4)
    - ARROW_SPLIT_CMD_LEFT  = 100 (0x64)
    - ARROW_SPLIT_CMD_RIGHT = 101 (0x65)
"""

from __future__ import annotations

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
    root = Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Create arrow command enum")
        try:
            e = EnumDataType(CategoryPath("/Imperialism"), "EArrowSplitCommandId", 4)
            e.add("ARROW_SPLIT_CMD_LEFT", 100)
            e.add("ARROW_SPLIT_CMD_RIGHT", 101)
            dt = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)

        program.save("create arrow command enum", None)
        print(f"[done] enum={dt.getPathName()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

