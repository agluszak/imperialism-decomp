#!/usr/bin/env python3
"""Gate TGreatPower hygiene anti-patterns with a ratcheting baseline."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.ratchet import compare, read_baseline, write_baseline
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("thunk_decl", re.compile(r"^\s*undefined4\s+thunk_[A-Za-z0-9_]+\s*\(", re.MULTILINE)),
    ("thunk_cast", re.compile(r"reinterpret_cast<[^>]+>\(\s*thunk_[A-Za-z0-9_]+\s*\)")),
    ("kaddr_literal", re.compile(r"\bkAddr[A-Za-z0-9_]+\b")),
    ("provisional_name", re.compile(r"\b[A-Za-z0-9_]*_Provisional\b")),
)

KEYS = [key for key, _ in PATTERNS]


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        default=str(repo_root / "config" / "baselines" / "tgreatpower_gate_baseline.csv"),
        help="CSV file with baseline per-file pattern counts.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write current counts as baseline and exit successfully.",
    )
    return parser.parse_args()


def scan_targets(repo_root: Path) -> list[Path]:
    targets: list[Path] = []
    for root in (repo_root / "src" / "game", repo_root / "include" / "game"):
        if not root.exists():
            continue
        for path in root.rglob("TGreatPower*"):
            if path.is_file() and path.suffix.lower() in {".h", ".hpp", ".cpp"}:
                targets.append(path)
    return sorted(set(targets))


def count_patterns(file_path: Path) -> dict[str, int]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    out: dict[str, int] = {}
    for key, pattern in PATTERNS:
        out[key] = len(pattern.findall(text))
    return out


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    current: dict[str, dict[str, int]] = {}
    for path in scan_targets(repo_root):
        rel = normalize_repo_relative_path(path, repo_root)
        counts = count_patterns(path)
        if sum(counts.values()) > 0:
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

    violations = compare(current, baseline, KEYS)

    if violations:
        print("TGreatPower hygiene gate failed:")
        for item in violations:
            print(f"  - {item}")
        print(f"Baseline: {baseline_path}")
        return 1

    tracked_total = sum(sum(v.values()) for v in current.values())
    print(
        f"TGreatPower hygiene gate passed. Files with baseline-tracked patterns: "
        f"{len(current)} (total matches: {tracked_total})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
