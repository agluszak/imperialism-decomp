#!/usr/bin/env python3
"""
Type city-region remap scratch table used by TMapMaker region reindex/compact passes.

Applies:
  - 0x006a3498 as int[256]
  - label: g_aiCityRegionIdRemapByLegacyIndex
  - removes stale inner label at 0x006a349c if present
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
        from ghidra.program.model.data import ArrayDataType, IntegerDataType
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        base = af.getAddress("0x006a3498")
        arr = ArrayDataType(IntegerDataType.dataType, 256, 4)
        end = base.add(arr.getLength() - 1)

        tx = program.startTransaction("Create city region remap table type")
        try:
            listing.clearCodeUnits(base, end, False)
            listing.createData(base, arr)

            primary = st.getPrimarySymbol(base)
            if primary is None:
                sym = st.createLabel(base, "g_aiCityRegionIdRemapByLegacyIndex", SourceType.USER_DEFINED)
                sym.setPrimary()
            elif primary.getName() != "g_aiCityRegionIdRemapByLegacyIndex":
                primary.setName("g_aiCityRegionIdRemapByLegacyIndex", SourceType.USER_DEFINED)

            # Remove stale inner label created before array typing.
            inner = af.getAddress("0x006a349c")
            for s in list(st.getSymbols(inner)):
                if s.getName() == "DAT_006a349c":
                    s.delete()

            cu = listing.getCodeUnitAt(base)
            if cu is not None:
                cu.setComment(
                    cu.EOL_COMMENT,
                    "Legacy->compact city-region id remap table (256 entries), initialized to -1 before rebuild passes.",
                )
        finally:
            program.endTransaction(tx, True)

        program.save("create city region remap table type", None)
        print("[done] typed g_aiCityRegionIdRemapByLegacyIndex as int[256]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

