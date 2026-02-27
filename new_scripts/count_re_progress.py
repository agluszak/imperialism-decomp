#!/usr/bin/env python3
"""
Quick reverse-engineering progress counters.

Usage:
  .venv/bin/python new_scripts/count_re_progress.py [project_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
RX_DEFAULT = re.compile(r"^(FUN_|thunk_FUN_)")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) >= 2 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        st = program.getSymbolTable()

        total = renamed = default_named = 0
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            total += 1
            if RX_DEFAULT.match(f.getName()):
                default_named += 1
            else:
                renamed += 1

        class_desc = vtbl = tname = 0
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            n = sit.next().getName()
            if n.startswith("g_pClassDescT"):
                class_desc += 1
            if n.startswith("g_vtblT"):
                # Count canonical class vtable roots only, not per-slot/auxiliary aliases.
                if "_Slot" in n or "Candidate_" in n or "Family_" in n:
                    continue
                vtbl += 1
            if n.startswith("g_szTypeNameT"):
                tname += 1

    print("total_functions", total)
    print("renamed_functions", renamed)
    print("default_fun_or_thunk_fun", default_named)
    print("class_desc_count", class_desc)
    print("vtbl_count", vtbl)
    print("type_name_count", tname)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
