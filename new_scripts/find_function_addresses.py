#!/usr/bin/env python3
"""
Find function addresses by exact name or substring.

Usage:
  .venv/bin/python new_scripts/find_function_addresses.py --exact ResetUiInputCaptureState
  .venv/bin/python new_scripts/find_function_addresses.py --contains TimeZone --limit 50
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
    ap.add_argument("--exact", help="Exact function name match")
    ap.add_argument("--contains", help="Case-insensitive substring match")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    if not args.exact and not args.contains:
        print("Provide --exact or --contains")
        return 1

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        exact = args.exact
        contains = args.contains.lower() if args.contains else None

        out = []
        it = fm.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            name = fn.getName()
            if exact and name != exact:
                continue
            if contains and contains not in name.lower():
                continue
            out.append((str(fn.getEntryPoint()), name, str(fn.getSignature())))

        out.sort(key=lambda x: x[0])
        for ep, name, sig in out[: args.limit]:
            print(f"{ep},{name},{sig}")
        print(f"[count] {len(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
