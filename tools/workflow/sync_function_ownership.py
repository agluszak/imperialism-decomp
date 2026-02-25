#!/usr/bin/env python3
"""Sync function ownership CSV from manual reccmp markers in source files."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.function_ownership import (
    DEFAULT_FUNCTION_OWNERSHIP_CSV,
    FunctionOwnership,
    function_marker_regex,
    load_function_ownership,
    normalize_repo_relative_path,
    write_function_ownership,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--source-dir", default="src")
    parser.add_argument("--ownership-csv", default=DEFAULT_FUNCTION_OWNERSHIP_CSV)
    parser.add_argument(
        "--prune-missing-manual",
        action="store_true",
        help="Remove existing non-autogen ownership entries not present in source markers.",
    )
    return parser.parse_args()


def should_skip_path(path: Path) -> bool:
    posix = path.as_posix()
    return "/ghidra_autogen/" in posix or "/autogen/" in posix


def iter_source_files(source_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx"):
        files.extend(sorted(source_dir.rglob(pattern)))
    return files


def collect_marker_ownership(
    source_dir: Path, repo_root: Path, target: str
) -> tuple[dict[int, FunctionOwnership], list[tuple[int, str, str]]]:
    marker_re = function_marker_regex(target)
    found: dict[int, FunctionOwnership] = {}
    conflicts: list[tuple[int, str, str]] = []

    for path in iter_source_files(source_dir):
        if should_skip_path(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        target_cpp = normalize_repo_relative_path(path, repo_root)
        for match in marker_re.finditer(text):
            address = int(match.group(1), 16)
            entry = FunctionOwnership(
                address=address,
                target_cpp=target_cpp,
                ownership="manual",
                note="marker_sync",
            )
            existing = found.get(address)
            if existing is None:
                found[address] = entry
                continue
            if existing.target_cpp != entry.target_cpp:
                conflicts.append((address, existing.target_cpp, entry.target_cpp))
    return found, conflicts


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    source_dir = resolve_repo_path(repo_root, args.source_dir)
    if not source_dir.is_dir():
        raise SystemExit(f"Missing source directory: {source_dir}")

    ownership_csv = resolve_repo_path(repo_root, args.ownership_csv)

    scanned_entries, conflicts = collect_marker_ownership(
        source_dir=source_dir, repo_root=repo_root, target=args.target
    )
    if conflicts:
        msg = ", ".join(
            f"0x{addr:08X}: {lhs} vs {rhs}" for addr, lhs, rhs in sorted(conflicts)
        )
        raise SystemExit("Conflicting ownership markers found: " + msg)

    merged = load_function_ownership(ownership_csv)
    stale_manual = 0
    if args.prune_missing_manual:
        for address in list(merged.keys()):
            entry = merged[address]
            if entry.ownership.lower() == "autogen":
                continue
            if address not in scanned_entries:
                stale_manual += 1
                del merged[address]

    updates = 0
    for address, entry in scanned_entries.items():
        if merged.get(address) != entry:
            updates += 1
        merged[address] = entry

    write_function_ownership(ownership_csv, merged)
    print(f"Scanned marker-owned functions: {len(scanned_entries)}")
    print(f"Ownership updates: {updates}")
    if args.prune_missing_manual:
        print(f"Pruned missing non-autogen ownership rows: {stale_manual}")
    print(f"Wrote {ownership_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
