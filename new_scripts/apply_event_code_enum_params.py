#!/usr/bin/env python3
"""
Apply event-code enum types to high-confidence event dispatch parameters.

Default behavior:
  - target functions whose names match event/dispatch patterns
  - target parameters named eventCode/nEventCode
  - replace only scalar integral parameter types (skip pointers/structs)

Usage:
  .venv/bin/python new_scripts/apply_event_code_enum_params.py
  .venv/bin/python new_scripts/apply_event_code_enum_params.py --apply
"""

from __future__ import annotations

import argparse
import re
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


def is_integral_nonptr(type_name: str) -> bool:
    t = type_name.strip().replace(" ", "").lower()
    if "*" in t:
        return False
    return t in {
        "byte",
        "char",
        "short",
        "ushort",
        "int",
        "uint",
        "long",
        "ulong",
        "undefined1",
        "undefined2",
        "undefined4",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--enum-path", default="/Imperialism/Enums/InterNationEventCode")
    ap.add_argument(
        "--function-name-regex",
        default=r"(TurnEvent|DialogEvent|Dispatch.*Event|FactorySlot|EventStateMachine)",
    )
    ap.add_argument("--param-name-regex", default=r"(^|_)(eventcode|neventcode)(_|$)")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    fn_re = re.compile(args.function_name_regex, re.IGNORECASE)
    param_re = re.compile(args.param_name_regex, re.IGNORECASE)

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        fm = program.getFunctionManager()
        enum_dt = dtm.getDataType(args.enum_path)
        if enum_dt is None:
            print(f"[error] missing enum: {args.enum_path}")
            return 1

        plans = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            name = fn.getName()
            if not fn_re.search(name):
                continue

            params = list(fn.getParameters())
            target_idxs = []
            for i, p in enumerate(params):
                pn = str(p.getName() or "")
                pt = str(p.getDataType().getName() or "")
                if not param_re.search(pn.replace(" ", "").lower()):
                    continue
                if not is_integral_nonptr(pt):
                    continue
                target_idxs.append(i)
            if target_idxs:
                plans.append((fn, target_idxs))

        print(f"[plan] functions={len(plans)} enum={enum_dt.getPathName()}")
        for fn, idxs in plans[:200]:
            ps = list(fn.getParameters())
            details = ", ".join(
                f"{i}:{ps[i].getName()}:{ps[i].getDataType().getName()}" for i in idxs
            )
            print(f"  {fn.getEntryPoint()} {fn.getName()} -> {details}")
        if len(plans) > 200:
            print(f"... ({len(plans)-200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply event-code enum parameter types")
        ok = skip = fail = 0
        try:
            for fn, idxs in plans:
                try:
                    old_sig = str(fn.getSignature())
                    old_params = list(fn.getParameters())
                    new_params = []
                    for i, p in enumerate(old_params):
                        dt = enum_dt if i in idxs else p.getDataType()
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
                    new_sig = str(fn.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {fn.getEntryPoint()} {fn.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply event-code enum parameter types", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

