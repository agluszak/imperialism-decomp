#!/usr/bin/env python3
"""
Create control-tag FourCC enum used in command-tag dispatch handlers.

Creates:
  /Imperialism/EControlTagFourCC (size 4)

Tags are stored as the little-endian 4-byte literals observed in code
(e.g. 'txen', 'yako', 'enod').
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TAG_LIST = [
    "yako",
    "lcnc",
    "cnac",
    "txen",
    "verp",
    "kcab",
    "ofni",
    "pleh",
    "tfel",
    "thgr",
    "ecca",
    "ejer",
    "tiaw",
    "enod",
    "dart",
    "nart",
    "aert",
    "kcip",
    "galf",
    "nalp",
    "bolg",
    "taoc",
    "dnes",
    "daol",
    "tiuq",
    "loot",
    "sruc",
]


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def tag_le_to_u32(tag: str) -> int:
    b = tag.encode("ascii", errors="strict")
    if len(b) != 4:
        raise ValueError(f"tag must be 4 bytes: {tag!r}")
    return int.from_bytes(b, byteorder="little", signed=False)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Create control tag enum")
        try:
            e = EnumDataType(CategoryPath("/Imperialism"), "EControlTagFourCC", 4)
            for tag_le in sorted(TAG_LIST):
                member = f"CONTROL_TAG_{tag_le.upper()}"
                e.add(member, tag_le_to_u32(tag_le))
            dt = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)

        program.save("create control tag enum", None)
        print(f"[done] enum={dt.getPathName()} entries={len(TAG_LIST)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
