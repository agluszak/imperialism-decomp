#!/usr/bin/env python3
"""
Apply EDiplomacyRelationCodeRaw to relationCode parameters in diplomacy helpers.
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
ENUM_PATH = "/Imperialism/EDiplomacyRelationCodeRaw"

TARGETS = {
    "SetNationPairDiplomacyRelationWithFinalFlag",
    "SetNationPairDiplomacyRelationAndApplySideEffects",
    "thunk_SetNationPairDiplomacyRelationWithFinalFlag",
    "thunk_SetNationPairDiplomacyRelationAndApplySideEffects",
}


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
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        enum_dt = dtm.getDataType(ENUM_PATH)
        if enum_dt is None:
            print(f"[error] missing enum {ENUM_PATH}")
            return 1

        plans = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            if fn.getName() not in TARGETS:
                continue
            params = list(fn.getParameters())
            idx = None
            for i, p in enumerate(params):
                if str(p.getName()) == "relationCode":
                    idx = i
                    break
            if idx is None:
                continue
            plans.append((fn, idx))

        print(f"[plan] functions={len(plans)} enum={ENUM_PATH}")
        for fn, idx in plans:
            p = list(fn.getParameters())[idx]
            print(
                f"  {fn.getEntryPoint()} {fn.getName()} param[{idx}] "
                f"{p.getName()}:{p.getDataType().getName()} -> {enum_dt.getName()}"
            )

        tx = program.startTransaction("Apply diplomacy relation param types")
        ok = skip = fail = 0
        try:
            for fn, idx in plans:
                try:
                    old_sig = str(fn.getSignature())
                    old_params = list(fn.getParameters())
                    new_params = []
                    for i, p in enumerate(old_params):
                        dt = enum_dt if i == idx else p.getDataType()
                        new_params.append(
                            ParameterImpl(
                                p.getName(),
                                dt,
                                program,
                                SourceType.USER_DEFINED,
                            )
                        )
                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    if str(fn.getSignature()) == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {fn.getEntryPoint()} {fn.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply diplomacy relation param types", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

