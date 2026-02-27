#!/usr/bin/env python3
"""
Create/apply typed TMapMakerGenerationState global block for mapgen quotas/RNG knobs.

Applies:
  - /Imperialism/MapGen/TMapMakerGenerationState (0x44 bytes)
  - 0x006a38bc as TMapMakerGenerationState
  - primary label: g_MapMakerGenerationState
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
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            StructureDataType,
            UnsignedIntegerDataType,
        )
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        tx = program.startTransaction("Create mapmaker generation state struct")
        try:
            cat = CategoryPath("/Imperialism/MapGen")
            u32 = UnsignedIntegerDataType.dataType

            s = StructureDataType(cat, "TMapMakerGenerationState", 0x44)
            s.replaceAtOffset(0x00, u32, 4, "uQuotaTokenD", "Mapgen quota token D.")
            s.replaceAtOffset(0x04, u32, 4, "uQuotaTokenH", "Mapgen quota token H.")
            s.replaceAtOffset(0x08, u32, 4, "uUnknown08", None)
            s.replaceAtOffset(0x0C, u32, 4, "uUnknown0C", None)
            s.replaceAtOffset(0x10, u32, 4, "uUnknown10", None)
            s.replaceAtOffset(0x14, u32, 4, "uUnknown14", None)
            s.replaceAtOffset(0x18, u32, 4, "uUnknown18", None)
            s.replaceAtOffset(0x1C, u32, 4, "uUnknown1C", None)
            s.replaceAtOffset(0x20, u32, 4, "uQuotaTokenS", "Mapgen quota token S.")
            s.replaceAtOffset(
                0x24, u32, 4, "uType3ExpansionAttempts", "Type-3 expansion attempt count."
            )
            s.replaceAtOffset(0x28, u32, 4, "uRngState", "Map generation RNG state.")
            s.replaceAtOffset(
                0x2C,
                u32,
                4,
                "uCityRegionSeedParamTokenC_A",
                "City-region seed parameter token C (A lane).",
            )
            s.replaceAtOffset(
                0x30,
                u32,
                4,
                "uCityRegionSeedParamTokenC_B",
                "City-region seed parameter token C (B lane).",
            )
            s.replaceAtOffset(0x34, u32, 4, "uUnknown34", None)
            s.replaceAtOffset(0x38, u32, 4, "uQuotaTokenF", "Mapgen quota token F.")
            s.replaceAtOffset(0x3C, u32, 4, "uUnknown3C", None)
            s.replaceAtOffset(0x40, u32, 4, "uUnknown40", None)

            s_dt = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

            base = af.getAddress("0x006a38bc")
            end = base.add(s_dt.getLength() - 1)
            listing.clearCodeUnits(base, end, False)
            listing.createData(base, s_dt)

            ps = st.getPrimarySymbol(base)
            if ps is None:
                sym = st.createLabel(base, "g_MapMakerGenerationState", SourceType.USER_DEFINED)
                sym.setPrimary()
            elif ps.getName() != "g_MapMakerGenerationState":
                ps.setName("g_MapMakerGenerationState", SourceType.USER_DEFINED)

            cu = listing.getCodeUnitAt(base)
            if cu is not None:
                cu.setComment(
                    cu.EOL_COMMENT,
                    "Map-maker generation state block (quotas, RNG seed/state, and region-seed parameters).",
                )
        finally:
            program.endTransaction(tx, True)

        program.save("create mapmaker generation state struct", None)
        print("[done] typed g_MapMakerGenerationState at 0x006a38bc")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
