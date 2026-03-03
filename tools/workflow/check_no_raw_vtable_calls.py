#!/usr/bin/env python3
"""Gate raw vtable patterns in gameplay code.

The gate compares current pattern counts against a checked-in baseline:
- New files with raw patterns fail.
- Existing files may not increase pattern counts.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("raw_vtable_index", re.compile(r"\(\*reinterpret_cast<void\*\*\*>\([^)]+\)\)\s*\[")),
    ("fn_typedef_cast", re.compile(r"reinterpret_cast<[^>]*Fn[^>]*>")),
    ("vftable_index", re.compile(r"\bvftable\s*\[")),
)

INFRA_ALLOWLIST: set[str] = {
    "include/game/vcall_runtime.h",
    "include/game/generated/vcall_facades.h",
}

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
        default=str(repo_root / "config" / "vtable_gate_baseline.csv"),
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
            if path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS:
                files.append(path)
    return sorted(set(files))


def count_patterns(file_path: Path) -> dict[str, int]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    counts: dict[str, int] = {}
    for key, pattern in PATTERNS:
        counts[key] = len(pattern.findall(text))
    return counts


def read_baseline(path: Path) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            file_key = (row.get("file") or "").strip()
            if not file_key:
                continue
            counts: dict[str, int] = {}
            for pattern_key, _ in PATTERNS:
                raw = (row.get(pattern_key) or "0").strip()
                counts[pattern_key] = int(raw) if raw else 0
            out[file_key] = counts
    return out


def write_baseline(path: Path, data: dict[str, dict[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["file"] + [key for key, _ in PATTERNS] + ["total"]
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|")
        writer.writeheader()
        for file_key in sorted(data):
            row = {"file": file_key}
            total = 0
            for pattern_key, _ in PATTERNS:
                value = data[file_key].get(pattern_key, 0)
                total += value
                row[pattern_key] = str(value)
            row["total"] = str(total)
            writer.writerow(row)


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
        write_baseline(baseline_path, current)
        print(f"Wrote baseline: {baseline_path} ({len(current)} files)")
        return 0

    baseline = read_baseline(baseline_path)
    if not baseline:
        print(f"Baseline missing: {baseline_path}")
        print("Run with --write-baseline once, then re-run the gate.")
        return 1

    violations: list[str] = []

    for file_key, counts in sorted(current.items()):
        base_counts = baseline.get(file_key)
        if base_counts is None:
            violations.append(f"{file_key}: new raw-vtable patterns introduced (not in baseline)")
            continue
        for pattern_key, _ in PATTERNS:
            current_count = counts.get(pattern_key, 0)
            base_count = base_counts.get(pattern_key, 0)
            if current_count > base_count:
                violations.append(
                    f"{file_key}: {pattern_key} increased {base_count} -> {current_count}"
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
