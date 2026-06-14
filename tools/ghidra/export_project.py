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

from tools.common import ghidra_env

_VENDOR_GHIDRA = Path(__file__).resolve().parents[2] / "vendor" / "ghidra"
DEFAULT_OUT = _VENDOR_GHIDRA / "exports" / "Imperialism.gzf"


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)

    project = ghidra_env.open_project(create=False)
    from java.io import File as JavaFile

    try:
        prog_leaf = ghidra_env.program_name().lstrip("/")
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
