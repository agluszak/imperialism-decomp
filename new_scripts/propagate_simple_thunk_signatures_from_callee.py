#!/usr/bin/env python3
"""
Propagate signatures from callee to trivial undefined thunk_ wrappers.

Candidate thunk patterns:
  1) JMP <func>
  2) CALL <func>; RET[/imm]

Safety gates:
  - thunk name starts with 'thunk_'
  - thunk signature currently starts with 'undefined '
  - target callee exists and has NON-undefined signature

Applied to thunk:
  - calling convention = callee's calling convention
  - return type = callee return type
  - parameters = cloned formal parameters from callee

Usage:
  .venv/bin/python new_scripts/propagate_simple_thunk_signatures_from_callee.py [--apply] [--project-root PATH]
"""

from __future__ import annotations

import argparse
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


def get_instructions(listing, body):
    out = []
    it = listing.getInstructions(body, True)
    while it.hasNext():
        out.append(it.next())
    return out


def resolve_target_function(fm, ins):
    refs = ins.getReferencesFrom()
    for ref in refs:
        callee = fm.getFunctionAt(ref.getToAddress())
        if callee is not None:
            return callee
    return None


def detect_simple_thunk_target(fm, listing, thunk):
    insns = get_instructions(listing, thunk.getBody())
    if len(insns) == 1 and str(insns[0].getMnemonicString()).upper() == "JMP":
        return resolve_target_function(fm, insns[0]), "JMP"
    if (
        len(insns) == 2
        and str(insns[0].getMnemonicString()).upper() == "CALL"
        and str(insns[1].getMnemonicString()).upper() == "RET"
    ):
        return resolve_target_function(fm, insns[0]), "CALL_RET"
    return None, None


def clone_params(program, callee):
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.program.model.symbol import SourceType

    out = []
    params = callee.getParameters()
    for i in range(len(params)):
        p = params[i]
        nm = p.getName() or f"param_{i+1}"
        out.append(ParameterImpl(nm, p.getDataType(), program, SourceType.USER_DEFINED))
    return out


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
        from ghidra.program.model.listing import Function
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        listing = program.getListing()

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            thunk = it.next()
            if not thunk.getName().startswith("thunk_"):
                continue
            if not str(thunk.getSignature()).startswith("undefined "):
                continue

            callee, shape = detect_simple_thunk_target(fm, listing, thunk)
            if callee is None:
                continue
            if str(callee.getSignature()).startswith("undefined "):
                continue
            candidates.append((thunk, callee, shape))

        print(f"[candidates] {len(candidates)}")
        for thunk, callee, shape in candidates[:220]:
            print(
                f"  {thunk.getEntryPoint()} {shape} {thunk.getName()} -> "
                f"{callee.getEntryPoint()} {callee.getName()} :: {callee.getSignature()}"
            )
        if len(candidates) > 220:
            print(f"  ... ({len(candidates) - 220} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Propagate simple thunk signatures from callee")
        ok = 0
        skip = 0
        fail = 0
        try:
            for thunk, callee, _shape in candidates:
                try:
                    old_sig = str(thunk.getSignature())
                    cc = callee.getCallingConventionName()
                    if cc:
                        thunk.setCallingConvention(cc)
                    params = clone_params(program, callee)
                    thunk.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        params,
                    )
                    thunk.setReturnType(callee.getReturnType(), SourceType.USER_DEFINED)
                    new_sig = str(thunk.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {thunk.getEntryPoint()} {thunk.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("propagate simple thunk signatures from callee", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
