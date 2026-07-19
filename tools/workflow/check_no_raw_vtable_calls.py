#!/usr/bin/env python3
"""Gate raw vtable patterns in gameplay code.

The gate compares current pattern counts against a checked-in baseline:
- New files with raw patterns fail.
- Existing files may not increase pattern counts.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path, strip_generated_blocks
from tools.common.ratchet import compare, read_baseline, write_baseline
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
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--roots",
        nargs="+",
        default=["src", "include"],
        help="Root paths to scan.",
    )
    parser.add_argument(
        "--baseline",
        default=str(repo_root / "config" / "baselines" / "vtable_gate_baseline.csv"),
        help="CSV file with baseline per-file pattern counts.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write current counts as baseline and exit successfully.",
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
            if is_excluded_scan_path(path):
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
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    current: dict[str, dict[str, int]] = {}
    for file_path in collect_files(repo_root, args.roots):
        rel = normalize_repo_relative_path(file_path, repo_root)
        if rel in INFRA_ALLOWLIST:
            continue
        counts = count_patterns(file_path)
        if sum(counts.values()) == 0:
            continue
        current[rel] = counts

    if args.write_baseline:
        write_baseline(baseline_path, current, KEYS)
        print(f"Wrote baseline: {baseline_path} ({len(current)} files)")
        return 0

    baseline = read_baseline(baseline_path, KEYS)
    if not baseline:
        print(f"Baseline missing: {baseline_path}")
        print("Run with --write-baseline once, then re-run the gate.")
        return 1

    violations = compare(
        current,
        baseline,
        KEYS,
        new_file_message=lambda file_key, _counts: (
            f"{file_key}: new raw-vtable patterns introduced (not in baseline)"
        ),
    )

    if violations:
        print("Raw vtable gate failed:")
        for item in violations:
            print(f"  - {item}")
        print(f"Baseline: {baseline_path}")
        return 1

    scanned_total = sum(sum(values.values()) for values in current.values())
    print(
        f"Raw vtable gate passed. Files with baseline-tracked patterns: {len(current)} "
        f"(total matches: {scanned_total})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
