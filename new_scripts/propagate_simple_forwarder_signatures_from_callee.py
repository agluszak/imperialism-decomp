#!/usr/bin/env python3
"""
Propagate signatures from callee to simple forwarders with undefined signatures.

Forwarder patterns:
  1) JMP <target>
  2) CALL <target>; RET[/imm]

Safety gates:
  - function name matches --name-regex
  - current signature starts with "undefined "
  - exactly one internal callee target is resolved from the forwarder shape
  - callee signature does NOT start with "undefined "

Applied to forwarder:
  - calling convention = callee's calling convention
  - return type = callee return type
  - parameters = cloned formal parameters from callee

Usage:
  .venv/bin/python new_scripts/propagate_simple_forwarder_signatures_from_callee.py
  .venv/bin/python new_scripts/propagate_simple_forwarder_signatures_from_callee.py --apply
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
            ep_txt = str(callee.getEntryPoint())
            if not ep_txt.startswith("EXTERNAL:"):
                return callee
    return None


def detect_simple_forward_target(fm, listing, func):
    insns = get_instructions(listing, func.getBody())
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
        "--name-regex",
        default=r"^(thunk_|WrapperFor_|FUN_|Cluster_.*Hint_)",
        help="Function name regex filter",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    name_re = re.compile(args.name_regex)
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
            f = it.next()
            if not name_re.search(f.getName()):
                continue
            if not str(f.getSignature()).startswith("undefined "):
                continue

            callee, shape = detect_simple_forward_target(fm, listing, f)
            if callee is None:
                continue
            if str(callee.getSignature()).startswith("undefined "):
                continue
            candidates.append((f, callee, shape))

        print(f"[candidates] {len(candidates)}")
        for f, callee, shape in candidates[:240]:
            print(
                f"  {f.getEntryPoint()} {shape} {f.getName()} -> "
                f"{callee.getEntryPoint()} {callee.getName()} :: {callee.getSignature()}"
            )
        if len(candidates) > 240:
            print(f"  ... ({len(candidates) - 240} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Propagate simple forwarder signatures from callee")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, callee, _shape in candidates:
                try:
                    old_sig = str(f.getSignature())
                    cc = callee.getCallingConventionName()
                    if cc:
                        f.setCallingConvention(cc)
                    params = clone_params(program, callee)
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        params,
                    )
                    f.setReturnType(callee.getReturnType(), SourceType.USER_DEFINED)
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

        program.save("propagate simple forwarder signatures from callee", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

