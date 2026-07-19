#!/usr/bin/env python3
"""Reject generated artifacts committed relative to a chosen merge base."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from tools.common.repo import repo_root_from_file


GENERATED_PREFIXES = (
    "build-msvc500/",
    "src/autogen/",
    "src/ghidra_autogen/",
    "include/ghidra_autogen/",
    "resources/generated/",
)


def changed_paths(repo_root: Path, base: str, no_worktree: bool) -> list[str]:
    command = ["git", "diff", "--name-only", base]
    if no_worktree:
        command.append("HEAD")
    proc = subprocess.run(command, cwd=repo_root, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or "git diff failed")
    return [path for path in proc.stdout.splitlines() if path]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="merge-base revision to inspect")
    parser.add_argument(
        "--no-worktree",
        action="store_true",
        help="compare only committed HEAD changes (for CI checkouts)",
    )
    args = parser.parse_args()

    repo_root = repo_root_from_file(__file__)
    offenders = [
        path
        for path in changed_paths(repo_root, args.base, args.no_worktree)
        if path.startswith(GENERATED_PREFIXES)
    ]
    if offenders:
        print("Generated artifacts must not be committed:")
        for path in offenders:
            print(f"  {path}")
        return 1

    print("Generated-artifact integrity gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
