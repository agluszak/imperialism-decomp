#!/usr/bin/env python3
"""
Create a trade bitmap enum and apply focused type/comment dehardcoding.

Actions:
  - Create/update /Imperialism/ETradeUiBitmapId (ushort)
  - Retype parameter nPictureId of thunk_SetPictureResourceIdAndRefresh (0x00408454)
  - Add EOL comments for trade bitmap constants in key trade functions
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

SET_PICTURE_FN = 0x00408454

TARGET_FUNCTIONS = [
    0x004601B0,  # InitializeTradeScreenBitmapControls
    0x0046503C,  # BuildTradeBoardDialogUiLayoutVariantA
    0x0046BAA7,  # BuildTradeBoardDialogUiLayoutVariantB
    0x00587980,  # IsTradeBidControlActionable
    0x00587A10,  # IsTradeOfferControlActionable
    0x00587AA0,  # SetTradeBidSecondaryBitmapState
    0x00587BB0,  # SetTradeBidControlBitmapState
    0x00587DD0,  # SetTradeOfferControlBitmapState
    0x00588030,  # SetTradeOfferSecondaryBitmapState
    0x00584520,  # HandleCardOrOfferTagClickAndDispatchTradeActions
]

ENUM_VALUES = [
    ("TRADE_BMP_BACKGROUND_PRE_OIL", 2101),
    ("TRADE_BMP_BACKGROUND_POST_OIL", 2102),
    ("TRADE_BMP_BID_STATE_A", 2111),
    ("TRADE_BMP_BID_SECONDARY_STATE_A", 2112),
    ("TRADE_BMP_OFFER_STATE_A", 2113),
    ("TRADE_BMP_OFFER_SECONDARY_STATE_A", 2114),
    ("TRADE_BMP_DERIVED_2119", 2119),  # derived runtime state
    ("TRADE_BMP_GREEN_CONTROL_BASE", 2120),
    ("TRADE_BMP_DECREASE_ARROW_BASE", 2121),
    ("TRADE_BMP_DECREASE_ARROW_PRESSED_DERIVED", 2122),
    ("TRADE_BMP_INCREASE_ARROW_BASE", 2123),
    ("TRADE_BMP_INCREASE_ARROW_PRESSED_DERIVED", 2124),
    ("TRADE_BMP_BID_STATE_B", 2125),
    ("TRADE_BMP_BID_SECONDARY_STATE_B", 2126),
    ("TRADE_BMP_OFFER_STATE_B", 2127),
    ("TRADE_BMP_OFFER_SECONDARY_STATE_B", 2128),
]

VALUE_TO_NAME = {v: n for n, v in ENUM_VALUES}


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
        from ghidra.program.model.listing import CodeUnit, Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        dtm = program.getDataTypeManager()

        tx = program.startTransaction("Create/apply trade bitmap enum")
        changed_comments = 0
        try:
            e = EnumDataType(CategoryPath("/Imperialism"), "ETradeUiBitmapId", 2)
            for name, val in ENUM_VALUES:
                e.add(name, val)
            enum_dt = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
            print(f"[enum] {enum_dt.getPathName()} values={len(ENUM_VALUES)}")

            # Retype nPictureId parameter on core picture setter.
            f = fm.getFunctionAt(af.getAddress(f"0x{SET_PICTURE_FN:08x}"))
            if f is not None:
                sig = f.getSignature()
                old_params = [sig.getArguments()[i] for i in range(sig.getArguments().length)]
                new_params = []
                for i, p in enumerate(old_params):
                    nm = p.getName()
                    dt = p.getDataType()
                    if i == 1:
                        dt = enum_dt
                        nm = "ePictureId"
                    elif i == 2 and nm.startswith("param_"):
                        nm = "fRefreshNow"
                    elif i == 0 and nm.startswith("param_"):
                        nm = "this"
                    new_params.append(ParameterImpl(nm, dt, program, SourceType.USER_DEFINED))

                f.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    new_params,
                )
                f.setCallingConvention("__thiscall")
                print(f"[typed] 0x{SET_PICTURE_FN:08x} {f.getName()}")
            else:
                print(f"[warn] missing function 0x{SET_PICTURE_FN:08x}")

            # EOL comments for literal bitmap constants.
            for faddr in TARGET_FUNCTIONS:
                fn = fm.getFunctionAt(af.getAddress(f"0x{faddr:08x}"))
                if fn is None:
                    continue
                it = listing.getInstructions(fn.getBody(), True)
                while it.hasNext():
                    ins = it.next()
                    for op_idx in range(ins.getNumOperands()):
                        for obj in ins.getOpObjects(op_idx):
                            val = None
                            if hasattr(obj, "getUnsignedValue"):
                                try:
                                    val = int(obj.getUnsignedValue())
                                except Exception:
                                    val = None
                            if val is None and hasattr(obj, "getValue"):
                                try:
                                    val = int(obj.getValue())
                                except Exception:
                                    val = None
                            if val is None:
                                continue
                            if val in VALUE_TO_NAME:
                                c = f"ETradeUiBitmapId::{VALUE_TO_NAME[val]} ({val})"
                                old = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
                                if old and c in old:
                                    continue
                                new_c = c if not old else f"{old} | {c}"
                                listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, new_c)
                                changed_comments += 1
                                break

            print(f"[comments] changed={changed_comments}")
        finally:
            program.endTransaction(tx, True)

        program.save("create/apply trade bitmap enum", None)
        print("[saved]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

