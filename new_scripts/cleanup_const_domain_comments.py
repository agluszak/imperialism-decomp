#!/usr/bin/env python3
"""
Remove stale [ConstDomain] lines from function comments.

Usage:
  .venv/bin/python new_scripts/cleanup_const_domain_comments.py [--project-root PATH]
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
MARKER = "[ConstDomain]"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def strip_marker_lines(comment: str) -> str:
    if MARKER not in comment:
        return comment
    kept = [ln for ln in comment.splitlines() if MARKER not in ln]
    return "\n".join(kept).strip()


def main() -> int:
    ap = argparse.ArgumentParser()
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
        tx = program.startTransaction("Cleanup ConstDomain comments")
        touched = 0
        try:
            it = fm.getFunctions(True)
            while it.hasNext():
                f = it.next()
                old = f.getComment() or ""
                if MARKER not in old:
                    continue
                new = strip_marker_lines(old)
                if new == old:
                    continue
                f.setComment(new if new else None)
                touched += 1
        finally:
            program.endTransaction(tx, True)

        program.save("cleanup const-domain comments", None)
        print(f"[done] comments_cleaned={touched}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
