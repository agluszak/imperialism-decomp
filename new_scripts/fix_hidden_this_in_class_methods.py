#!/usr/bin/env python3
"""
Fix hidden-this class methods that still decompile with `in_ECX`.

Conservative selection:
  - function is in a class namespace (default regex: ^T)
  - function has zero formal params
  - decompiled C contains token `in_ECX`
  - class datatype exists

Applied signature shape:
  __thiscall <ret> Func(<ClassName>* pThis)

Usage:
  .venv/bin/python new_scripts/fix_hidden_this_in_class_methods.py --dry-run
  .venv/bin/python new_scripts/fix_hidden_this_in_class_methods.py --apply
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


def find_datatype_by_name(dtm, name: str):
    from ghidra.program.model.data import CategoryPath

    dt = dtm.getDataType(CategoryPath("/imperialism/classes"), name)
    if dt is not None:
        return dt

    it = dtm.getAllDataTypes()
    while it.hasNext():
        cand = it.next()
        if cand.getName() == name:
            return cand
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument("--dry-run", action="store_true", help="Preview only")
    ap.add_argument(
        "--class-regex",
        default=r"^T(Map|MacViewMgr|Application|ViewMgr|WorldView|AssetMgr|ArmyMgr|CivMgr)",
        help="Regex of class namespaces to inspect",
    )
    ap.add_argument(
        "--max-print",
        type=int,
        default=200,
        help="Max candidates to print",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    do_apply = args.apply and not args.dry_run
    class_re = re.compile(args.class_regex)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.data import PointerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        ifc = DecompInterface()
        ifc.openProgram(program)

        class_ptr_types = {}
        candidates = []

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            cls = ns.getName()
            if not class_re.search(cls):
                continue

            params = list(f.getParameters())
            if len(params) != 0:
                continue

            res = ifc.decompileFunction(f, 20, None)
            if not res or not res.decompileCompleted():
                continue
            c_code = res.getDecompiledFunction().getC()
            if "in_ECX" not in c_code:
                continue

            if cls not in class_ptr_types:
                cdt = find_datatype_by_name(dtm, cls)
                if cdt is None:
                    continue
                class_ptr_types[cls] = PointerDataType(cdt)

            candidates.append((f, cls))

        print(f"[candidates] {len(candidates)} class_regex={args.class_regex}")
        for f, cls in candidates[: args.max_print]:
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            print(f"  0x{addr:08x} {cls}::{f.getName()} sig={f.getSignature()}")
        if len(candidates) > args.max_print:
            print(f"  ... ({len(candidates) - args.max_print} more)")

        if not do_apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Fix hidden this in class methods")
        ok = skip = fail = 0
        try:
            for f, cls in candidates:
                try:
                    old_sig = str(f.getSignature())
                    f.setCallingConvention("__thiscall")

                    p_this = ParameterImpl(
                        "pThis",
                        class_ptr_types[cls],
                        program,
                        SourceType.USER_DEFINED,
                    )
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [p_this],
                    )
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
                    print(f"[fail] 0x{addr:08x} {cls}::{f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("fix hidden this in class methods", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

