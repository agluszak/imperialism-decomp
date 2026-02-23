#!/usr/bin/env python3
"""Run clang-format over repository C/C++ sources."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
DEFAULT_ROOTS = ("src")
EXCLUDE_PARTS = ("src/autogen/", "src/ghidra_autogen/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if formatting changes are needed; do not edit files.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_ROOTS),
        help="Files or directories to format (default: src include).",
    )
    return parser.parse_args()


def is_cpp_path(path: Path) -> bool:
    return path.suffix.lower() in CPP_EXTS


def should_exclude(path: Path) -> bool:
    norm = path.as_posix()
    return any(part in norm for part in EXCLUDE_PARTS)


def collect_paths(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            continue
        if p.is_file():
            if is_cpp_path(p) and not should_exclude(p):
                out.append(p)
            continue
        for candidate in p.rglob("*"):
            if candidate.is_file() and is_cpp_path(candidate) and not should_exclude(candidate):
                out.append(candidate)
    return sorted(set(out))


def run_clang_format(binary: str, files: list[Path], check: bool) -> int:
    if not files:
        print("No C/C++ files found.")
        return 0

    cmd = [binary]
    if check:
        cmd += ["--dry-run", "--Werror"]
    else:
        cmd += ["-i"]
    cmd += [str(p) for p in files]

    proc = subprocess.run(cmd, check=False)
    return proc.returncode


def main() -> int:
    args = parse_args()
    clang_format = shutil.which("clang-format")
    if clang_format is None:
        print("clang-format not found in PATH.", file=sys.stderr)
        return 2

    files = collect_paths(args.paths)
    return run_clang_format(clang_format, files, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
