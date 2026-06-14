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

import sys
from pathlib import Path

import pyghidra

from tools.common import ghidra_env

_VENDOR_GHIDRA = Path(__file__).resolve().parents[2] / "vendor" / "ghidra"
EXPORTS_DIR = _VENDOR_GHIDRA / "exports"
DEFAULT_GZF = EXPORTS_DIR / "Imperialism.gzf"


def resolve_gzf() -> Path | None:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    if DEFAULT_GZF.is_file():
        return DEFAULT_GZF
    # Fall back to the newest archive in the exports dir.
    candidates = sorted(EXPORTS_DIR.glob("*.gzf"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else None


def main() -> int:
    gzf = resolve_gzf()
    if gzf is None or not gzf.is_file():
        print(f"ERROR: no .gzf export found in {EXPORTS_DIR}", file=sys.stderr)
        return 2

    project = ghidra_env.open_project(create=True)
    from java.io import File as JavaFile

    try:
        pdata = project.getProjectData()
        root = pdata.getRootFolder()
        prog_leaf = ghidra_env.program_name().lstrip("/")

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
