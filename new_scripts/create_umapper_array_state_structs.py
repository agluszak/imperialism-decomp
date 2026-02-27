#!/usr/bin/env python3
"""
Create/apply UMapper overlay array-state structs at global anchors.

Applies:
  - 0x006a3478 as TOverlayQuadBorderLinkArrayState16
  - 0x006a3900 as TOverlaySpanRecordArrayState24
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
            PointerDataType,
            StructureDataType,
            UnsignedIntegerDataType,
            VoidDataType,
        )
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        quad_rec = dtm.getDataType("/Imperialism/UMapper/TOverlayQuadBorderLinkRecord16")
        span_rec = dtm.getDataType("/Imperialism/UMapper/TOverlaySpanRecord24")
        if quad_rec is None or span_rec is None:
            print(
                "[error] missing prerequisite types; run create_umapper_overlay_types.py first"
            )
            return 1

        tx = program.startTransaction("Create/apply UMapper array-state structs")
        try:
            cat = CategoryPath("/Imperialism/UMapper")
            p_void = PointerDataType(VoidDataType.dataType)
            u32 = UnsignedIntegerDataType.dataType

            quad_state = StructureDataType(cat, "TOverlayQuadBorderLinkArrayState16", 0x10)
            quad_state.replaceAtOffset(0x0, p_void, 4, "pStateBase", None)
            quad_state.replaceAtOffset(
                0x4, PointerDataType(quad_rec), 4, "pQuadBorderLinkArray16Buffer", None
            )
            quad_state.replaceAtOffset(0x8, u32, 4, "uQuadBorderLinkArray16Capacity", None)
            quad_state.replaceAtOffset(0xC, u32, 4, "uQuadBorderLinkArray16Count", None)
            quad_state_dt = dtm.addDataType(quad_state, DataTypeConflictHandler.REPLACE_HANDLER)

            span_state = StructureDataType(cat, "TOverlaySpanRecordArrayState24", 0x18)
            span_state.replaceAtOffset(0x0, p_void, 4, "pStateBase", None)
            span_state.replaceAtOffset(
                0x4, PointerDataType(span_rec), 4, "pOverlaySpanRecordArray18Buffer", None
            )
            span_state.replaceAtOffset(0x8, u32, 4, "uOverlaySpanRecordArray18Capacity", None)
            span_state.replaceAtOffset(0xC, u32, 4, "uOverlaySpanRecordArray18Count", None)
            span_state.replaceAtOffset(
                0x10,
                u32,
                4,
                "uSuppressRoutePointPairMismatchAssert",
                "When non-zero, suppresses route-point pair mismatch assertion path.",
            )
            span_state.replaceAtOffset(
                0x14,
                u32,
                4,
                "uSuppressSpanEndpointLinkAssert",
                "When non-zero, suppresses span endpoint-link assertion path.",
            )
            span_state_dt = dtm.addDataType(span_state, DataTypeConflictHandler.REPLACE_HANDLER)

            quad_addr = af.getAddress("0x006a3478")
            span_addr = af.getAddress("0x006a3900")

            listing.clearCodeUnits(quad_addr, quad_addr.add(quad_state_dt.getLength() - 1), False)
            listing.createData(quad_addr, quad_state_dt)
            listing.clearCodeUnits(span_addr, span_addr.add(span_state_dt.getLength() - 1), False)
            listing.createData(span_addr, span_state_dt)

            for addr, name, cmt in [
                (
                    quad_addr,
                    "g_OverlayQuadBorderLinkArray16State",
                    "UMapper quad-border-link array manager (buffer/capacity/count).",
                ),
                (
                    span_addr,
                    "g_OverlaySpanRecordArray18State",
                    "UMapper overlay-span array manager (buffer/capacity/count + assert-suppression guards).",
                ),
            ]:
                ps = st.getPrimarySymbol(addr)
                if ps is None:
                    s = st.createLabel(addr, name, SourceType.USER_DEFINED)
                    s.setPrimary()
                elif ps.getName() != name:
                    ps.setName(name, SourceType.USER_DEFINED)
                cu = listing.getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment(cu.EOL_COMMENT, cmt)
        finally:
            program.endTransaction(tx, True)

        program.save("create umapper array-state structs", None)
        print("[done] applied UMapper array-state structs")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
