#!/usr/bin/env python3
"""
Attach thunk target implementations into class namespaces using unique owner thunks.

Pattern:
  - source function is in a class namespace
  - source function is a simple forwarder:
      1) JMP target
      2) CALL target ; RET
  - target function currently in global namespace

Ownership:
  - target may have multiple class thunk owners
  - apply only when target has exactly one owning class (unique-owner safety gate)

Usage:
  .venv/bin/python new_scripts/attach_class_thunk_targets.py
  .venv/bin/python new_scripts/attach_class_thunk_targets.py --apply
"""

from __future__ import annotations

import argparse
from collections import defaultdict
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write namespace attachments")
    ap.add_argument("--max-print", type=int, default=250)
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
        fm = program.getFunctionManager()
        listing = program.getListing()
        global_ns = program.getGlobalNamespace()

        # target_ep -> set(class_name)
        owners = defaultdict(set)
        # target_ep -> representative tuple(target_func, class_ns, src_func, shape)
        sample = {}

        it = fm.getFunctions(True)
        while it.hasNext():
            src = it.next()
            src_ns = src.getParentNamespace()
            if src_ns == global_ns:
                continue
            if src_ns is None or src_ns.getName() == "Global":
                continue

            target, shape = detect_simple_forward_target(fm, listing, src)
            if target is None:
                continue
            if target.getParentNamespace() != global_ns:
                continue

            ep = str(target.getEntryPoint())
            owners[ep].add(src_ns.getName())
            if ep not in sample:
                sample[ep] = (target, src_ns, src, shape)

        unique = []
        ambiguous = 0
        for ep, cls_names in owners.items():
            if len(cls_names) != 1:
                ambiguous += 1
                continue
            target, src_ns, src, shape = sample[ep]
            unique.append((target, src_ns, src, shape))

        unique.sort(key=lambda t: str(t[0].getEntryPoint()))
        print(
            "[summary] "
            f"targets_with_class_thunk_owner={len(owners)} "
            f"unique_targets={len(unique)} "
            f"ambiguous_targets={ambiguous}"
        )
        for target, src_ns, src, shape in unique[: args.max_print]:
            print(
                f"{target.getEntryPoint()} {target.getName()} <- "
                f"{src_ns.getName()} via {src.getName()} ({shape})"
            )
        if len(unique) > args.max_print:
            print(f"... ({len(unique) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write attachments")
            return 0

        tx = program.startTransaction("Attach class thunk targets")
        ok = 0
        skip = 0
        fail = 0
        try:
            for target, cls_ns, _src, _shape in unique:
                try:
                    if target.getParentNamespace() == cls_ns:
                        skip += 1
                        continue
                    target.setParentNamespace(cls_ns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {target.getEntryPoint()} {target.getName()} -> {cls_ns.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach class thunk targets", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

