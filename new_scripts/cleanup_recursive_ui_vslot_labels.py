#!/usr/bin/env python3
"""
Delete recursively-generated UI vslot labels.

Targets only labels that look like nested slot expansions, e.g.:
  g_vtblFoo_Slot0094_..._Slot01D0_...

Usage:
  .venv/bin/python new_scripts/cleanup_recursive_ui_vslot_labels.py
  .venv/bin/python new_scripts/cleanup_recursive_ui_vslot_labels.py --apply
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

NESTED_RE = re.compile(
    r"_Slot[0-9A-Fa-f]{4}_.+_Slot[0-9A-Fa-f]{4}_"
)


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
    ap.add_argument("--apply", action="store_true", help="Delete matched labels")
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

        matches = []
        it = st.getSymbolIterator()
        while it.hasNext():
            sym = it.next()
            n = sym.getName()
            if not n.startswith("g_vtbl"):
                continue
            if not NESTED_RE.search(n):
                continue
            matches.append(sym)

        print(f"[candidates] {len(matches)}")
        for sym in matches[:200]:
            print(f"  {sym.getAddress()} {sym.getName()}")
        if len(matches) > 200:
            print(f"  ... ({len(matches) - 200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to delete")
            return 0

        tx = program.startTransaction("Cleanup recursive ui vslot labels")
        ok = 0
        fail = 0
        try:
            for sym in matches:
                try:
                    sym.delete()
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {sym.getAddress()} {sym.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("cleanup recursive ui vslot labels", None)
        print(f"[done] deleted={ok} failed={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
