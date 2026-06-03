#!/usr/bin/env python3
"""Pack the live Ghidra working project into the vendored portable .gzf archive.

The live project (GHIDRA_PROJECT_DIR, default vendor/ghidra) is the working copy and
is gitignored; this packs its program into `vendor/ghidra/exports/Imperialism.gzf`
(committed via Git LFS) plus a `.sha256`, so the archive can be refreshed after
Ghidra-side changes (e.g. after `just import-ghidra`). Run `just export-project`,
then commit the updated archive. Fresh clones recreate the live project with
`just restore-project`.

Usage:
  GHIDRA_INSTALL_DIR=... uv run python -m tools.ghidra.export_project [out.gzf]
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pyghidra

_VENDOR_GHIDRA = Path(__file__).resolve().parents[2] / "vendor" / "ghidra"
PROJECT_DIR = os.getenv("GHIDRA_PROJECT_DIR", str(_VENDOR_GHIDRA))
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")
DEFAULT_OUT = _VENDOR_GHIDRA / "exports" / "Imperialism.gzf"


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
    from java.io import File as JavaFile

    project = pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False)
    try:
        prog_leaf = PROGRAM_NAME.lstrip("/")
        df = project.getProjectData().getRootFolder().getFile(prog_leaf)
        if df is None:
            print(f"ERROR: program not found in project: /{prog_leaf}", file=sys.stderr)
            return 2

        tmp = out.with_name(out.name + ".tmp")
        if tmp.exists():
            tmp.unlink()
        print(f"Packing /{prog_leaf} -> {out} ...")
        df.packFile(JavaFile(str(tmp)), pyghidra.task_monitor())
        os.replace(tmp, out)

        digest = hashlib.sha256(out.read_bytes()).hexdigest()
        out.with_name(out.name + ".sha256").write_text(f"{digest}  {out.name}\n")
        print(f"Wrote {out} ({out.stat().st_size} bytes)")
        print(f"  sha256 {digest}")
        return 0
    finally:
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
