#!/usr/bin/env python3
"""One-time: create the Ghidra project and restore the committed .gzf export.

The repo ships the program as a packed Ghidra archive (exports/*.gzf via git-LFS)
rather than a live .gpr project. This creates/opens the project named by
GHIDRA_PROJECT_NAME under GHIDRA_PROJECT_DIR and restores the .gzf as
GHIDRA_PROGRAM_NAME if it is not already present.

Usage:
  GHIDRA_INSTALL_DIR=... uv run python -m tools.ghidra.restore_project [path/to/export.gzf]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyghidra

PROJECT_DIR = os.getenv("GHIDRA_PROJECT_DIR", "/home/agluszak/code/decomp/imperialism_knowledge")
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")
DEFAULT_GZF = "/home/agluszak/code/decomp/imperialism_knowledge/exports/Imperialism-20260217_003824.gzf"


def main() -> int:
    gzf = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GZF)
    if not gzf.is_file():
        print(f"ERROR: export not found: {gzf}", file=sys.stderr)
        return 2

    pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
    from java.io import File as JavaFile

    project = pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=True)
    try:
        pdata = project.getProjectData()
        root = pdata.getRootFolder()
        prog_leaf = PROGRAM_NAME.lstrip("/")

        existing = root.getFile(prog_leaf)
        if existing is not None:
            print(f"Program already present: /{prog_leaf} ({existing.getContentType()})")
            return 0

        print(f"Restoring {gzf.name} -> /{prog_leaf} ...")
        df = root.createFile(
            prog_leaf,
            JavaFile(str(gzf)),
            pyghidra.task_monitor(),
        )
        print(f"Restored: {df.getPathname()} ({df.getContentType()})")
        return 0
    finally:
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
