#!/usr/bin/env python3
"""
Attach global functions to class namespaces using strict name prefixes.

Accepted patterns:
- TClassName_MethodName...
- thunk_TClassName_MethodName...

Safety gates:
- Function must currently be in Global namespace.
- Parsed class namespace must already exist.

Usage:
  .venv/bin/python new_scripts/attach_class_methods_by_prefix.py
  .venv/bin/python new_scripts/attach_class_methods_by_prefix.py --apply
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
RX = re.compile(r"^(?:thunk_)?(T[A-Za-z0-9]+)_")


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
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        candidates = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            if f.getParentNamespace() != global_ns:
                continue
            m = RX.match(f.getName())
            if not m:
                continue
            cname = m.group(1)
            cns = class_map.get(cname)
            if cns is None:
                continue
            candidates.append((f, cname, cns))

        print(f"[summary] unique_global_candidates={len(candidates)}")
        for f, cname, _ in candidates[: args.max_print]:
            print(f"{f.getEntryPoint()} {f.getName()} -> {cname}")
        if len(candidates) > args.max_print:
            print(f"... ({len(candidates) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write attachments")
            return 0

        tx = program.startTransaction("Attach class methods by strict prefix")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, _cname, cns in candidates:
                try:
                    if f.getParentNamespace() == cns:
                        skip += 1
                        continue
                    f.setParentNamespace(cns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach class methods by strict prefix", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
