#!/usr/bin/env python3
"""
Create/apply core UMapper overlay record types and normalize key globals.

Applies:
  - /Imperialism/UMapper/TOverlayQuadBorderLinkRecord16
  - /Imperialism/UMapper/TOverlaySpanRecord24
  - pointer typing at:
      0x006a347c -> TOverlayQuadBorderLinkRecord16 *
      0x006a3904 -> TOverlaySpanRecord24 *
  - label normalization for quad-border-link array globals:
      0x006a3478, 0x006a347c, 0x006a3480, 0x006a3484
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
            IntegerDataType,
            PointerDataType,
            ShortDataType,
            StructureDataType,
            UnsignedIntegerDataType,
        )
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        cat = CategoryPath("/Imperialism/UMapper")

        tx = program.startTransaction("Create UMapper overlay types")
        try:
            quad = StructureDataType(cat, "TOverlayQuadBorderLinkRecord16", 0x10)
            quad.replaceAtOffset(0x0, IntegerDataType.dataType, 4, "nQuadCellId", None)
            quad.replaceAtOffset(0x4, IntegerDataType.dataType, 4, "nEdgeVertexA", None)
            quad.replaceAtOffset(0x8, IntegerDataType.dataType, 4, "nEdgeVertexB", None)
            quad.replaceAtOffset(0xC, IntegerDataType.dataType, 4, "nEdgeDirection", None)
            quad_dt = dtm.addDataType(quad, DataTypeConflictHandler.REPLACE_HANDLER)

            span = StructureDataType(cat, "TOverlaySpanRecord24", 0x18)
            span.replaceAtOffset(0x0, ShortDataType.dataType, 2, "sStartX", None)
            span.replaceAtOffset(0x2, ShortDataType.dataType, 2, "sStartY", None)
            span.replaceAtOffset(0x4, ShortDataType.dataType, 2, "sEndX", None)
            span.replaceAtOffset(0x6, ShortDataType.dataType, 2, "sEndY", None)
            span.replaceAtOffset(0x8, IntegerDataType.dataType, 4, "nRouteNodeIndexA", None)
            span.replaceAtOffset(0xC, IntegerDataType.dataType, 4, "nRouteNodeIndexB", None)
            span.replaceAtOffset(0x10, ShortDataType.dataType, 2, "sRegionIdA", None)
            span.replaceAtOffset(0x12, ShortDataType.dataType, 2, "sRegionIdB", None)
            span.replaceAtOffset(0x14, ShortDataType.dataType, 2, "sLinkPrevIndex", None)
            span.replaceAtOffset(0x16, ShortDataType.dataType, 2, "sLinkNextIndex", None)
            span_dt = dtm.addDataType(span, DataTypeConflictHandler.REPLACE_HANDLER)

            typed_globals = [
                (
                    0x006A347C,
                    PointerDataType(quad_dt),
                    "g_pOverlayQuadBorderLinkArray16Buffer",
                    "Pointer to 0x10-byte quad-border-link records used to build overlay spans.",
                ),
                (
                    0x006A3904,
                    PointerDataType(span_dt),
                    "g_pOverlaySpanRecordArray18Buffer",
                    "Pointer to 0x18-byte overlay span records used by region merge/rebuild passes.",
                ),
            ]

            for addr_i, dtype, label, comment in typed_globals:
                addr = af.getAddress(f"0x{addr_i:08x}")
                listing.clearCodeUnits(addr, addr.add(3), False)
                listing.createData(addr, dtype)
                ps = st.getPrimarySymbol(addr)
                if ps is None:
                    s = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    s.setPrimary()
                elif ps.getName() != label:
                    ps.setName(label, SourceType.USER_DEFINED)
                cu = listing.getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment(cu.EOL_COMMENT, comment)

            quad_globals = [
                (
                    0x006A3478,
                    "g_OverlayQuadBorderLinkArray16State",
                    "State/base object used by quad-border-link array helper calls.",
                ),
                (
                    0x006A3480,
                    "g_uOverlayQuadBorderLinkArray16Capacity",
                    "Capacity (entry count) of quad-border-link array buffer.",
                ),
                (
                    0x006A3484,
                    "g_uOverlayQuadBorderLinkArray16Count",
                    "Active entry count in quad-border-link array buffer.",
                ),
                (
                    0x006A3900,
                    "g_OverlaySpanRecordArray18State",
                    "State/base object used by overlay-span array helper calls.",
                ),
                (
                    0x006A3908,
                    "g_uOverlaySpanRecordArray18Capacity",
                    "Capacity (entry count) of overlay-span record buffer.",
                ),
                (
                    0x006A390C,
                    "g_uOverlaySpanRecordArray18Count",
                    "Active entry count in overlay-span record buffer.",
                ),
            ]
            for addr_i, label, comment in quad_globals:
                addr = af.getAddress(f"0x{addr_i:08x}")
                ps = st.getPrimarySymbol(addr)
                if ps is None:
                    s = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    s.setPrimary()
                elif ps.getName() != label:
                    ps.setName(label, SourceType.USER_DEFINED)
                cu = listing.getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment(cu.EOL_COMMENT, comment)

            # Preserve existing mapgen RNG as unsigned for clarity.
            rng_addr = af.getAddress("0x006A38E8")
            listing.clearCodeUnits(rng_addr, rng_addr.add(3), False)
            listing.createData(rng_addr, UnsignedIntegerDataType.dataType)

        finally:
            program.endTransaction(tx, True)

        program.save("create umapper overlay types", None)
        print("[done] created/applied UMapper overlay types and globals")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

