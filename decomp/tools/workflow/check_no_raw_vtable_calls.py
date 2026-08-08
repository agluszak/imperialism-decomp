#!/usr/bin/env python3
"""Gate raw vtable patterns in gameplay code (Hard Rule 13).

Baseline-free HARD BAN: any raw-vtable pattern (raw vftable indexing, Fn-typedef
reinterpret_cast, VCall_ facade) in manual source fails the gate. The debt was
fully eradicated, so there is no baseline file and no update escape hatch --
re-introducing one is always a regression to fix.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path, strip_generated_blocks
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("raw_vtable_index", re.compile(r"\(\*reinterpret_cast<void\*\*\*>\([^)]+\)\)\s*\[")),
    ("fn_typedef_cast", re.compile(r"reinterpret_cast<[^>]*Fn[^>]*>")),
    ("vftable_index", re.compile(r"\bvftable\s*\[")),
    ("vcall_facade", re.compile(r"\bVCall_[A-Za-z0-9_]+\s*\(")),
)

KEYS = [key for key, _ in PATTERNS]

INFRA_ALLOWLIST: set[str] = set()

DEFAULT_EXTENSIONS = {".h", ".hpp", ".c", ".cc", ".cpp"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--roots",
        nargs="+",
        default=["src", "include"],
        help="Root paths to scan.",
    )
    return parser.parse_args()


def collect_files(repo_root: Path, roots: list[str]) -> list[Path]:
    files: list[Path] = []
    for root_value in roots:
        root = resolve_repo_path(repo_root, root_value)
        if not root.exists():
            continue
        if root.is_file():
            if root.suffix.lower() in DEFAULT_EXTENSIONS:
                files.append(root)
            continue
        for path in root.rglob("*"):
            if is_excluded_scan_path(path, roots=[root]):
                continue
            if not (path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS):
                continue
            # ghidra_autogen is regenerated reference output (never compiled,
            # hand-editing forbidden): its raw-vtable pattern counts change with
            # every DB resync and are not a source-policy signal (Hard Rule 13
            # targets manual source).
            if "/ghidra_autogen/" in path.as_posix():
                continue
            files.append(path)
    return sorted(set(files))


def count_patterns(file_path: Path) -> dict[str, int]:
    text = strip_generated_blocks(file_path.read_text(encoding="utf-8", errors="ignore"))
    counts: dict[str, int] = {}
    for key, pattern in PATTERNS:
        counts[key] = len(pattern.findall(text))
    return counts


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    current: dict[str, dict[str, int]] = {}
    for file_path in collect_files(repo_root, args.roots):
        rel = normalize_repo_relative_path(file_path, repo_root)
        if rel in INFRA_ALLOWLIST:
            continue
        counts = count_patterns(file_path)
        if sum(counts.values()) == 0:
            continue
        current[rel] = counts

    if current:
        print("Raw vtable gate failed (hard ban -- zero occurrences allowed):")
        for rel in sorted(current):
            present = ", ".join(k for k in KEYS if current[rel].get(k, 0))
            print(f"  - {rel}: raw-vtable pattern(s) [{present}]")
        print("See AGENTS.md Hard Rule 13 / construction Hard Rule 9: use real virtual methods.")
        print("This is a hard ban with no baseline: fix the source, do not bless it.")
        return 1

    print("Raw vtable gate passed (hard ban -- zero offenders).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
