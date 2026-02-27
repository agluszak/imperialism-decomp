#!/usr/bin/env python3
"""
Apply signatures for known wrapper families where decompiled prototypes are stable.

Current families:
  - WrapperFor_HandleCityDialogNoOpSlot14_At*
  - WrapperFor_HandleCityDialogNoOpSlot18_At*

Rule:
  - decompiled header must contain "__thiscall"
  - decompiled header must show exactly two params: (int param_1, int *param_2)-shape
  - apply: void __thiscall func(void * this, void * pMessage)

Usage:
  .venv/bin/python new_scripts/apply_wrapper_family_signatures.py [--apply] [--project-root PATH]
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


def extract_header(c_code: str) -> str:
    m = re.search(r"^(.*?)\n\{", c_code, re.S)
    if not m:
        return ""
    lines = [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]
    return lines[-1] if lines else ""


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

    families = (
        "WrapperFor_HandleCityDialogNoOpSlot14_At",
        "WrapperFor_HandleCityDialogNoOpSlot18_At",
    )

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.data import PointerDataType, VoidDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        ifc = DecompInterface()
        ifc.openProgram(program)

        void_t = VoidDataType.dataType
        void_ptr = PointerDataType(VoidDataType.dataType)

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            name = f.getName()
            if not any(name.startswith(prefix) for prefix in families):
                continue
            res = ifc.decompileFunction(f, 20, None)
            if not res.decompileCompleted():
                continue
            c_code = res.getDecompiledFunction().getC()
            header = extract_header(c_code)
            # Strict gate to avoid bad bulk typing.
            if "__thiscall" not in header:
                continue
            if re.search(r"\(\s*int\s+param_1\s*,\s*int\s*\*\s*param_2\s*\)", header) is None:
                continue
            candidates.append((f, header))

        print(f"[candidates] {len(candidates)}")
        for f, header in candidates:
            print(f"  {f.getEntryPoint()} {f.getName()} | {header}")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply wrapper family signatures")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, _ in candidates:
                try:
                    old_sig = str(f.getSignature())
                    p_msg = ParameterImpl("pMessage", void_ptr, program, SourceType.USER_DEFINED)
                    f.setCallingConvention("__thiscall")
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [p_msg],
                    )
                    f.setReturnType(void_t, SourceType.USER_DEFINED)
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

        program.save("apply wrapper family signatures", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
