#!/usr/bin/env python3
"""
Count DAT_* global symbols that still have at least one incoming reference.

Usage:
  .venv/bin/python new_scripts/count_dat_with_refs.py
"""

from __future__ import annotations

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
    root = Path(__file__).resolve().parents[1]
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    dat_with_refs = 0
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        rm = program.getReferenceManager()

        it = st.getAllSymbols(True)
        while it.hasNext():
            sym = it.next()
            name = sym.getName()
            if not name.startswith("DAT_"):
                continue
            refs = rm.getReferenceCountTo(sym.getAddress())
            if refs > 0:
                dat_with_refs += 1

    print(f"dat_with_refs {dat_with_refs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
