#!/usr/bin/env python3
"""
Apply high-confidence runtime global names/types for:
  - UI resource pool state cluster (0x006a13e0..0x006a13f8)
  - empty-string sentinel (0x006a13a0)
  - display manager/runtime render globals (0x006a2158, 0x006a1d60)
  - quickdraw context companion globals (0x006950f8, 0x006a1ca0, 0x006a1da0, 0x006a1db0, 0x006a1dbc)

This pass is intentionally conservative and evidence-backed from:
  - RegisterUiResourceEntry
  - PopUiResourcePoolNode
  - thunk_PushUiResourcePoolNode
  - InitializeGlobalRuntimeSystemsFromConfig
  - SetActiveQuickDrawSurfaceContext
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
            CategoryPath,
            DataTypeConflictHandler,
            IntegerDataType,
            PointerDataType,
            StructureDataType,
            VoidDataType,
        )
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()
        dtm = program.getDataTypeManager()

        p_void = PointerDataType(VoidDataType.dataType)
        i32 = IntegerDataType.dataType
        u8 = ByteDataType.dataType

        def set_primary_label(addr_int: int, name: str):
            addr = af.getAddress(f"0x{addr_int:08x}")
            ps = st.getPrimarySymbol(addr)
            if ps is None:
                sym = st.createLabel(addr, name, SourceType.USER_DEFINED)
                sym.setPrimary()
                return
            if ps.getName() != name:
                ps.setName(name, SourceType.USER_DEFINED)

        def set_comment(addr_int: int, text: str):
            addr = af.getAddress(f"0x{addr_int:08x}")
            cu = listing.getCodeUnitAt(addr)
            if cu is not None:
                cu.setComment(cu.EOL_COMMENT, text)

        cat = CategoryPath("/imperialism/runtime")
        ui_pool_struct = StructureDataType(cat, "TUiResourcePoolState", 0x1C)
        ui_pool_struct.replaceAtOffset(
            0x00, p_void, 4, "pReservedOrOwner", "unknown/reserved slot"
        )
        ui_pool_struct.replaceAtOffset(
            0x04, p_void, 4, "pChainHead", "oldest node in active chain"
        )
        ui_pool_struct.replaceAtOffset(
            0x08, p_void, 4, "pChainTop", "newest/current node in active chain"
        )
        ui_pool_struct.replaceAtOffset(0x0C, i32, 4, "nDepth", "active pool depth")
        ui_pool_struct.replaceAtOffset(
            0x10, p_void, 4, "pFreeListHead", "head of reusable node free-list"
        )
        ui_pool_struct.replaceAtOffset(
            0x14, p_void, 4, "pBlockChainHead", "linked allocation block chain"
        )
        ui_pool_struct.replaceAtOffset(
            0x18, i32, 4, "nNodesPerBlock", "node count allocated per block"
        )

        tx = program.startTransaction("Apply UI pool/render globals")
        ok = fail = 0
        try:
            dtm.addDataType(ui_pool_struct, DataTypeConflictHandler.REPLACE_HANDLER)

            # Apply struct and labels for pool state cluster.
            pool_addr = af.getAddress("0x006a13e0")
            pool_end = pool_addr.add(0x1C - 1)
            listing.clearCodeUnits(pool_addr, pool_end, False)
            listing.createData(pool_addr, ui_pool_struct)
            set_primary_label(0x006A13E0, "g_UiResourcePoolState")
            set_comment(
                0x006A13E0,
                "Global UI resource-pool state object used by Push/Pop/RegisterUiResourceEntry paths.",
            )

            set_primary_label(0x006A13E4, "g_pUiResourcePoolChainHead")
            set_comment(0x006A13E4, "Oldest node in active UI resource-pool chain.")
            set_primary_label(0x006A13E8, "g_pUiResourcePoolChainTop")
            set_comment(0x006A13E8, "Newest/current node in active UI resource-pool chain.")
            set_primary_label(0x006A13EC, "g_nUiResourcePoolDepth")
            set_comment(0x006A13EC, "Active UI resource-pool depth counter.")
            set_primary_label(0x006A13F0, "g_pUiResourcePoolFreeListHead")
            set_comment(0x006A13F0, "Reusable node free-list head for UI resource pool.")
            set_primary_label(0x006A13F4, "g_pUiResourcePoolBlockChainHead")
            set_comment(0x006A13F4, "Linked allocation-block head for UI resource pool backing memory.")
            set_primary_label(0x006A13F8, "g_nUiResourcePoolNodesPerBlock")
            set_comment(0x006A13F8, "Allocation node count per linked block.")
            ok += 1

            # Empty-string sentinel byte.
            a = af.getAddress("0x006a13a0")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, u8)
            set_primary_label(0x006A13A0, "g_szEmptyString")
            set_comment(0x006A13A0, "Global empty-string sentinel used as default C-string source.")
            ok += 1

            # Display manager/runtime pointer.
            a = af.getAddress("0x006a2158")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, p_void)
            set_primary_label(0x006A2158, "g_pDisplayManager")
            set_comment(
                0x006A2158,
                "Global display/runtime render manager created during InitializeGlobalRuntimeSystemsFromConfig.",
            )
            ok += 1

            # Active quickdraw surface context (render-path alias).
            a = af.getAddress("0x006a1d60")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, p_void)
            set_primary_label(0x006A1D60, "g_pActiveQuickDrawSurfaceContext")
            set_comment(
                0x006A1D60,
                "Currently active quickdraw surface context selected by SetActiveQuickDrawSurfaceContext.",
            )
            ok += 1

            # Quickdraw selector/context companions.
            a = af.getAddress("0x006950f8")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, p_void)
            set_primary_label(0x006950F8, "g_pCurrentQuickDrawSurfaceContext")
            set_comment(
                0x006950F8,
                "Canonical selected quickdraw surface context pointer returned by GetActiveQuickDrawSurfaceContextAndFlags.",
            )

            a = af.getAddress("0x006a1ca0")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, p_void)
            set_primary_label(0x006A1CA0, "g_DefaultQuickDrawSurfaceContext")
            set_comment(
                0x006A1CA0,
                "Default quickdraw surface-context sentinel used as the non-owning fallback target.",
            )

            a = af.getAddress("0x006a1da0")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, p_void)
            set_primary_label(0x006A1DA0, "g_pQuickDrawActiveMemoryDc")
            set_comment(
                0x006A1DA0,
                "Active heap-allocated CDC wrapper for quickdraw compatible DC operations.",
            )

            a = af.getAddress("0x006a1db0")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, i32)
            set_primary_label(0x006A1DB0, "g_nQuickDrawContextFlags")
            set_comment(
                0x006A1DB0,
                "Quickdraw context flags paired with g_pCurrentQuickDrawSurfaceContext.",
            )

            a = af.getAddress("0x006a1dbc")
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, p_void)
            set_primary_label(0x006A1DBC, "g_hQuickDrawPreviousSelectedObject")
            set_comment(
                0x006A1DBC,
                "GDI object previously selected into g_pQuickDrawActiveMemoryDc for restoration on context switch.",
            )
            ok += 1
        except Exception as ex:
            fail += 1
            print(f"[fail] {ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply ui pool and render globals", None)
        print(f"[done] ok={ok} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
