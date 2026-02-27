#!/usr/bin/env python3
"""
Apply map-interaction globals (labels + datatypes + comments) for mode-4 preview lane.

Targets include:
  - primary render surface context pointer
  - mode-4 preview surface context pointer
  - preview/order offset init flags
  - preview/order rect offsets
  - preview scale factors and quantized offset
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
            ByteDataType,
            DoubleDataType,
            IntegerDataType,
            PointerDataType,
            VoidDataType,
        )
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        p_void = PointerDataType(VoidDataType.dataType)
        i32 = IntegerDataType.dataType
        u8 = ByteDataType.dataType
        f64 = DoubleDataType.dataType

        entries = [
            (
                0x006A30A8,
                "g_pPrimaryRenderSurfaceContext",
                p_void,
                "Primary render surface context used by strategic/tactical/diplomacy overlay blits.",
            ),
            (
                0x006A3450,
                "g_pMapInteractionPreviewSurfaceContext",
                p_void,
                "Map interaction preview surface context; defaults to primary context and may be replaced by temporary buffers.",
            ),
            (
                0x006A344C,
                "g_bMapInteractionPreviewOffsetInitialized",
                u8,
                "One-time initialization guard for map-interaction preview offset constants.",
            ),
            (
                0x006A3418,
                "g_nMapInteractionPreviewOffsetX",
                i32,
                "X offset applied to map-interaction preview rects before blit.",
            ),
            (
                0x006A341C,
                "g_nMapInteractionPreviewOffsetY",
                i32,
                "Y offset applied to map-interaction preview rects before blit.",
            ),
            (
                0x006A33F8,
                "g_bMapOrderPreviewOffsetInitialized",
                u8,
                "One-time initialization guard for map-order preview offset constants.",
            ),
            (
                0x006A3440,
                "g_nMapOrderPreviewOffsetX",
                i32,
                "X offset applied to map-order tile preview atlas blits.",
            ),
            (
                0x006A3444,
                "g_nMapOrderPreviewOffsetY",
                i32,
                "Y offset applied to map-order tile preview atlas blits.",
            ),
            (
                0x006A3410,
                "g_f64MapInteractionPreviewScaleX",
                f64,
                "Double scale factor used by mode-4 interaction preview projection math (X lane).",
            ),
            (
                0x006A33D0,
                "g_f64MapInteractionPreviewScaleY",
                f64,
                "Double scale factor used by mode-4 interaction preview projection math (Y lane).",
            ),
            (
                0x006A3448,
                "g_nMapInteractionPreviewVerticalOffsetQuantized",
                i32,
                "Quantized vertical preview offset derived from scale factors and converted via __ftol.",
            ),
        ]

        tx = program.startTransaction("Apply map interaction mode4 globals")
        ok = fail = 0
        try:
            for addr_i, name, dtype, comment in entries:
                try:
                    addr = af.getAddress(f"0x{addr_i:08x}")
                    end = addr.add(dtype.getLength() - 1)
                    listing.clearCodeUnits(addr, end, False)
                    listing.createData(addr, dtype)

                    ps = st.getPrimarySymbol(addr)
                    if ps is None:
                        s = st.createLabel(addr, name, SourceType.USER_DEFINED)
                        s.setPrimary()
                    elif ps.getName() != name:
                        ps.setName(name, SourceType.USER_DEFINED)

                    cu = listing.getCodeUnitAt(addr)
                    if cu is not None:
                        cu.setComment(cu.EOL_COMMENT, comment)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{addr_i:08x} {name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply map interaction mode4 globals", None)
        print(f"[done] ok={ok} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
