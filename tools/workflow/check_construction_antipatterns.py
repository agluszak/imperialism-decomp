#!/usr/bin/env python3
"""Gate real-C++-construction anti-patterns in gameplay code.

Enforces the mechanically-checkable subset of the "real C++ construction and
inheritance" Hard Rules in AGENTS.md. Like the raw-vtable gate, it compares
current per-file pattern counts against a checked-in baseline:
- New files with any tracked pattern fail.
- Existing files may not increase a pattern's count.

The baseline lets pre-existing, knowingly-temporary bridges stay (tracked so they
ratchet downward) while blocking any new occurrence. Patterns that should never
appear (inline asm, placement-new on this, manual vptr writes, thiscall
reinterpret_cast) carry a baseline of 0, so the first new occurrence fails.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Hard Rule 1: no inline assembly.
    ("inline_asm", re.compile(r"\b(?:__asm|_asm)\b|\basm\s*\(")),
    # Construction rule 7: placement-new on this is not base construction.
    ("placement_new_this", re.compile(r"\bnew\s*\(\s*this\s*\)")),
    # Construction rule 2: no manual vtable-pointer writes.
    ("manual_vptr_write", re.compile(r"\*\s*\(\s*void\s*\*\*\s*\)\s*this\s*=|\bvptr\s*=\s*g_vtbl")),
    # Heuristic note: never reinterpret_cast to a __thiscall function pointer.
    ("thiscall_cast", re.compile(r"reinterpret_cast<[^>]*__thiscall[^>]*>")),
    # Construction rules 8/16: temporary construction-bridge helper names.
    ("bridge_name", re.compile(r"\b(?:Construct\w*AtThis|VCall_\w*Runtime|\w*AndMaybeFree)\b")),
    # Banned porting approach: class operator new/delete used as a construction factory.
    # Port real methods + real inheritance instead. (Baseline-tracked: ratchet down.)
    ("operator_new_delete", re.compile(r"\boperator\s+(?:new|delete)\s*\(")),
)

# Low-level runtime files that may legitimately contain raw construction mechanics,
# documented in-place. Keep this list minimal.
INFRA_ALLOWLIST: set[str] = {
    "include/game/vcall_runtime.h",
    "include/game/generated/vcall_facades.h",
}

DEFAULT_EXTENSIONS = {".h", ".hpp", ".c", ".cc", ".cpp"}
GENERATED_MARKERS = ("/ghidra_autogen/", "/autogen/stubs/")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", nargs="+", default=["src", "include"], help="Root paths to scan.")
    parser.add_argument(
        "--baseline",
        default=str(repo_root / "config" / "construction_gate_baseline.csv"),
        help="CSV file with baseline per-file pattern counts.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write current counts as baseline and exit successfully.",
    )
    return parser.parse_args()


def is_generated(rel: str) -> bool:
    return any(marker in f"/{rel}" for marker in GENERATED_MARKERS)


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
    return {key: len(pattern.findall(text)) for key, pattern in PATTERNS}


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
        if rel in INFRA_ALLOWLIST or is_generated(rel):
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
            present = ", ".join(k for k, _ in PATTERNS if counts.get(k, 0))
            violations.append(f"{file_key}: new construction anti-pattern(s) [{present}] (not in baseline)")
            continue
        for pattern_key, _ in PATTERNS:
            current_count = counts.get(pattern_key, 0)
            base_count = base_counts.get(pattern_key, 0)
            if current_count > base_count:
                violations.append(f"{file_key}: {pattern_key} increased {base_count} -> {current_count}")

    if violations:
        print("Construction anti-pattern gate failed:")
        for item in violations:
            print(f"  - {item}")
        print("See AGENTS.md 'Hard rules: real C++ construction and inheritance'.")
        print(f"Baseline: {baseline_path}")
        return 1

    scanned_total = sum(sum(values.values()) for values in current.values())
    print(
        f"Construction anti-pattern gate passed. Baseline-tracked files: {len(current)} "
        f"(total matches: {scanned_total})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
