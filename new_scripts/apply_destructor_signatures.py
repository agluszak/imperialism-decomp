#!/usr/bin/env python3
"""
Batch-apply signatures for class-style destructors:
  DestructT*AndMaybeFree

Heuristic gate (default):
  - function name matches pattern
  - decompiled body references FreeHeapBufferIfNotNull
  - decompiled body uses a low-bit free flag check ("& 1")

Applied signature:
  void * __thiscall DestructT*AndMaybeFree(T* this, byte freeSelfFlag)

Usage:
  .venv/bin/python new_scripts/apply_destructor_signatures.py [--apply] [--project-root PATH]
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
        from ghidra.program.model.data import ByteDataType, PointerDataType, VoidDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        pattern = re.compile(r"^DestructT.+AndMaybeFree$")

        ifc = DecompInterface()
        ifc.openProgram(program)

        byte_t = ByteDataType.dataType
        void_ptr = PointerDataType(VoidDataType.dataType)

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            name = f.getName()
            if not pattern.match(name):
                continue
            res = ifc.decompileFunction(f, 20, None)
            if not res.decompileCompleted():
                continue
            code = res.getDecompiledFunction().getC()
            if "FreeHeapBufferIfNotNull" not in code:
                continue
            if "& 1" not in code:
                continue
            candidates.append(f)

        print(f"[candidates] {len(candidates)}")
        for f in candidates:
            print(f"  {f.getEntryPoint()} {f.getName()} :: {f.getSignature()}")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply destructor signatures")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f in candidates:
                try:
                    old_sig = str(f.getSignature())
                    # Keep only formal flag parameter; __thiscall contributes implicit this.
                    p_flag = ParameterImpl("freeSelfFlag", byte_t, program, SourceType.USER_DEFINED)
                    f.setCallingConvention("__thiscall")
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [p_flag],
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

        program.save("apply destructor signatures", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
