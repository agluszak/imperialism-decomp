#!/usr/bin/env python3
"""
Create EDiplomacyProposalCodeRaw and apply focused diplomacy signatures.

Goals:
  - Dehardcode raw proposal/action IDs used in diplomacy validation flow.
  - Improve decompiler readability by fixing clear __thiscall signatures.

Applied targets:
  - 0x004ef700 ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode
  - 0x00408a94 thunk_ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode
  - 0x004f5e00 ResolveDiplomacyActionFromClickAndUpdateTarget
  - 0x00406ed3 thunk_ResolveDiplomacyActionFromClickAndUpdateTarget
  - 0x004f5410 HandleDiplomacySelectedNationActionCommand
  - 0x00408fee thunk_HandleDiplomacySelectedNationActionCommand
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

ENUM_VALUES = [
    ("DIPLOMACY_PROPOSAL_CODE_02", 0x02),
    ("DIPLOMACY_PROPOSAL_CODE_03", 0x03),
    ("DIPLOMACY_PROPOSAL_CODE_04", 0x04),
    ("DIPLOMACY_PROPOSAL_CODE_05", 0x05),
    ("DIPLOMACY_PROPOSAL_CODE_06", 0x06),
    ("DIPLOMACY_PROPOSAL_CODE_07", 0x07),
    ("DIPLOMACY_PROPOSAL_CODE_08", 0x08),
    ("DIPLOMACY_PROPOSAL_CODE_09", 0x09),
    ("DIPLOMACY_PROPOSAL_CODE_0A", 0x0A),
    ("DIPLOMACY_PROPOSAL_CODE_0B", 0x0B),
    ("DIPLOMACY_PROPOSAL_CODE_0C", 0x0C),
    ("DIPLOMACY_PROPOSAL_CODE_0D", 0x0D),
    ("DIPLOMACY_PROPOSAL_CODE_0E", 0x0E),
    ("DIPLOMACY_PROPOSAL_CODE_0F", 0x0F),
]


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
            EnumDataType,
            IntegerDataType,
            PointerDataType,
            ShortDataType,
            VoidDataType,
        )
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        tx = program.startTransaction("Create diplomacy proposal enum and apply signatures")
        try:
            enum_dt = EnumDataType(CategoryPath("/Imperialism"), "EDiplomacyProposalCodeRaw", 4)
            for name, val in ENUM_VALUES:
                enum_dt.add(name, val)
            enum_dt = dtm.addDataType(enum_dt, DataTypeConflictHandler.REPLACE_HANDLER)
            print(f"[enum] {enum_dt.getPathName()} values={len(ENUM_VALUES)}")

            short_dt = ShortDataType.dataType
            int_dt = IntegerDataType.dataType
            p_void = PointerDataType(VoidDataType.dataType)

            def set_sig(addr_hex: str, cc: str, ret_dt, params, note: str | None = None):
                fn = fm.getFunctionAt(af.getAddress(addr_hex))
                if fn is None:
                    print(f"[skip] missing {addr_hex}")
                    return
                fn.setCallingConvention(cc)
                fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    params,
                )
                fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
                if note:
                    old = fn.getComment() or ""
                    if note not in old:
                        fn.setComment(note if not old else f"{old}\n\n{note}")
                print(f"[typed] {addr_hex} {fn.getName()} :: {fn.getSignature()}")

            validate_params = [
                ParameterImpl("sourceNationSlot", short_dt, program, SourceType.USER_DEFINED),
                ParameterImpl("targetNationSlot", short_dt, program, SourceType.USER_DEFINED),
                ParameterImpl("eProposalCode", enum_dt, program, SourceType.USER_DEFINED),
            ]
            validate_note = (
                "[Typed] eProposalCode is raw diplomacy proposal/action code-space "
                "(currently validated for 0x02..0x0F in this function)."
            )
            set_sig("0x004ef700", "__thiscall", VoidDataType.dataType, validate_params, validate_note)
            set_sig("0x00408a94", "__thiscall", VoidDataType.dataType, validate_params, None)

            resolve_params = [
                ParameterImpl("pCursorPoint", p_void, program, SourceType.USER_DEFINED),
            ]
            resolve_note = (
                "[Typed] Returns selected diplomacy proposal/action code from current click context."
            )
            set_sig("0x004f5e00", "__thiscall", enum_dt, resolve_params, resolve_note)
            set_sig("0x00406ed3", "__thiscall", enum_dt, resolve_params, None)

            handle_params = [
                ParameterImpl("pCursorPoint", p_void, program, SourceType.USER_DEFINED),
            ]
            set_sig(
                "0x004f5410",
                "__thiscall",
                VoidDataType.dataType,
                handle_params,
                "[Typed] Handles selected-nation diplomacy action using click-context point.",
            )
            set_sig("0x00408fee", "__thiscall", VoidDataType.dataType, handle_params, None)
        finally:
            program.endTransaction(tx, True)

        program.save("create diplomacy proposal enum and apply signatures", None)
        print("[saved]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
