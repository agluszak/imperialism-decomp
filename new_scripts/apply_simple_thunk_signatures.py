#!/usr/bin/env python3
"""
Apply conservative signatures to trivial thunk_ wrappers.

Target functions must satisfy all:
  - name starts with 'thunk_'
  - current signature starts with 'undefined '
  - instruction pattern is exactly one of:
      1) JMP <target>
      2) CALL <target>; RET[/imm]

Applied signature:
  void __cdecl thunk_*(void)

Usage:
  .venv/bin/python new_scripts/apply_simple_thunk_signatures.py [--apply] [--project-root PATH]
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


def collect_mnemonics(listing, body):
    out = []
    it = listing.getInstructions(body, True)
    while it.hasNext():
        ins = it.next()
        out.append((str(ins.getMnemonicString()).upper(), str(ins)))
    return out


def is_simple_thunk_pattern(mnems: list[tuple[str, str]]) -> bool:
    if len(mnems) == 1:
        return mnems[0][0] == "JMP"
    if len(mnems) == 2:
        return mnems[0][0] == "CALL" and mnems[1][0] == "RET"
    return False


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
        from ghidra.program.model.data import VoidDataType
        from ghidra.program.model.listing import Function
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        listing = program.getListing()

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            n = f.getName()
            if not n.startswith("thunk_"):
                continue
            if not str(f.getSignature()).startswith("undefined "):
                continue
            mnems = collect_mnemonics(listing, f.getBody())
            if not is_simple_thunk_pattern(mnems):
                continue
            candidates.append((f, mnems))

        print(f"[candidates] {len(candidates)}")
        for f, mnems in candidates[:200]:
            shape = "; ".join(m for _, m in mnems)
            print(f"  {f.getEntryPoint()} {f.getName()} :: {shape}")
        if len(candidates) > 200:
            print(f"  ... ({len(candidates) - 200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply simple thunk signatures")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, _ in candidates:
                try:
                    old_sig = str(f.getSignature())
                    f.setCallingConvention("__cdecl")
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [],
                    )
                    f.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
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

        program.save("apply simple thunk signatures", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
