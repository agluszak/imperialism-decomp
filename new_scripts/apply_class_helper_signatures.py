#!/usr/bin/env python3
"""
Batch-apply low-risk signatures for class helper functions.

Targets:
  - GetT*ClassNamePointer            -> void * func(void)
  - CreateT*Instance                 -> void * func(void) [must call AllocateWithFallbackHandler]
  - ConstructT*BaseState             -> void * func(void) [must call AllocateWithFallbackHandler]

Usage:
  .venv/bin/python new_scripts/apply_class_helper_signatures.py [--apply] [--project-root PATH]
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write signature changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.data import PointerDataType, VoidDataType
        from ghidra.program.model.listing import Function
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        ifc = DecompInterface()
        ifc.openProgram(program)

        void_ptr = PointerDataType(VoidDataType.dataType)

        pat_get = re.compile(r"^GetT.+ClassNamePointer$")
        pat_create = re.compile(r"^CreateT.+Instance$")
        pat_ctor = re.compile(r"^ConstructT.+BaseState$")

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            name = f.getName()
            kind = None
            if pat_get.match(name):
                kind = "getter"
            elif pat_create.match(name):
                kind = "create"
            elif pat_ctor.match(name):
                kind = "ctor_alloc"
            if kind is None:
                continue

            res = ifc.decompileFunction(f, 20, None)
            if not res.decompileCompleted():
                continue
            code = res.getDecompiledFunction().getC()

            if kind in ("create", "ctor_alloc") and "AllocateWithFallbackHandler" not in code:
                continue

            candidates.append((f, kind))

        print(f"[candidates] total={len(candidates)}")
        for f, kind in candidates[:120]:
            print(f"  {f.getEntryPoint()} {kind:10} {f.getName()} :: {f.getSignature()}")
        if len(candidates) > 120:
            print(f"  ... ({len(candidates) - 120} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply class helper signatures")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, _kind in candidates:
                try:
                    old_sig = str(f.getSignature())
                    # These helpers are static-like and allocate/return pointers.
                    f.setCallingConvention("__cdecl")
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [],
                    )
                    f.setReturnType(void_ptr, SourceType.USER_DEFINED)
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply class helper signatures", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
