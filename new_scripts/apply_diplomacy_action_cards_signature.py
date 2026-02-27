#!/usr/bin/env python3
"""
Apply explicit signature to BuildNationActionOptionCardsFromRelationTable + thunk.

Evidence basis:
  - function currently decompiles with hidden `in_ECX` and stack cursors.
  - clear usage of two by-ref cursors (`*pRowCursor`, `*pColumnCursor`) and one
    nation/slot selector argument.
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
        from ghidra.program.model.data import IntegerDataType, PointerDataType, ShortDataType, VoidDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        short_dt = ShortDataType.dataType
        int_dt = IntegerDataType.dataType
        p_int = PointerDataType(int_dt)

        params = [
            ParameterImpl("sourceNationSlot", short_dt, program, SourceType.USER_DEFINED),
            ParameterImpl("pRowCursor", p_int, program, SourceType.USER_DEFINED),
            ParameterImpl("pColumnCursor", p_int, program, SourceType.USER_DEFINED),
        ]

        tx = program.startTransaction("Apply diplomacy action-card builder signature")
        try:
            for addr in ("0x0055c010", "0x0040713f"):
                fn = fm.getFunctionAt(af.getAddress(addr))
                if fn is None:
                    print(f"[skip] missing {addr}")
                    continue
                fn.setCallingConvention("__thiscall")
                fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    params,
                )
                fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
                note = (
                    "[Typed] Builds diplomacy action-option cards using row/column cursors; "
                    "raw proposal/action gating remains in code-space pending semantic mapping."
                )
                old = fn.getComment() or ""
                if note not in old:
                    fn.setComment(note if not old else f"{old}\n\n{note}")
                print(f"[typed] {addr} {fn.getName()} :: {fn.getSignature()}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply diplomacy action card builder signature", None)
        print("[saved]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
