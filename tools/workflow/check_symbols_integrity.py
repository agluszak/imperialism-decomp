#!/usr/bin/env python3
"""Structural integrity gate for config/symbols.csv.

Catches the failure modes that silently corrupt downstream tooling (every consumer
uses csv.DictReader, which trusts line 1 to be the header):
  - the header row must be exactly line 1 (a resort once moved it to EOF and broke
    vtable resolution for 364/379 vtables with no error anywhere),
  - no duplicate header rows elsewhere in the file,
  - every data row has at least the base column count and a hex-parseable address,
  - no duplicate addresses.

Also checks that no two `type=="function"` rows claim overlapping `[address,
address+size)` byte ranges — two independent functions never share .text bytes, so
an overlap proves one row's boundary is wrong (the "degenerate size clamps the
compare window" failure class in the sync-pipeline skill's junk taxonomy; see
`config/function_overlap_allowlist.txt` for pre-existing, tracked instances).

Deliberately NOT checked: global address sort order — the canonical writer
(merge_curated_symbols.write_symbols_csv) appends curated-only orphan rows after the
Ghidra-export-ordered block, so sortedness is not an invariant of the format.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.common.csv_integrity import check_pipe_csv_structure
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

BASE_COLUMNS = ["address", "name", "symbol", "size", "type", "prototype"]
OPTIONAL_COLUMNS = ["provenance"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--symbols-csv",
        default="config/symbols.csv",
        help="Pipe-delimited symbols table to verify.",
    )
    parser.add_argument(
        "--overlap-allowlist",
        default="config/function_overlap_allowlist.txt",
        help="Pre-existing outer:inner address overlaps to allow (one per line, '#' comments).",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=20,
        help="Stop printing after this many violations (still fails).",
    )
    return parser.parse_args()


def check_file(path: Path, max_errors: int) -> list[str]:
    return check_pipe_csv_structure(path, BASE_COLUMNS, OPTIONAL_COLUMNS, max_errors)


def load_function_ranges(rows: list[dict[str, str]]) -> list[tuple[int, int, str]]:
    """Return (start, end, name) for every function row with a parseable range."""
    ranges: list[tuple[int, int, str]] = []
    for row in rows:
        if (row.get("type") or "").strip() != "function":
            continue
        addr_text = (row.get("address") or "").strip().lower().removeprefix("0x")
        size_text = (row.get("size") or "").strip()
        try:
            addr = int(addr_text, 16)
            size = int(size_text)
        except ValueError:
            continue
        if size <= 0:
            continue
        ranges.append((addr, addr + size, row.get("name") or f"0x{addr:x}"))
    return ranges


def read_overlap_allowlist(path: Path) -> set[tuple[int, int]]:
    allowed: set[tuple[int, int]] = set()
    if not path.is_file():
        return allowed
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        outer, _, inner = entry.partition(":")
        allowed.add((int(outer.strip(), 16), int(inner.strip(), 16)))
    return allowed


def check_function_overlaps(
    ranges: list[tuple[int, int, str]], allowlist: set[tuple[int, int]]
) -> list[str]:
    violations: list[str] = []
    ordered = sorted(ranges, key=lambda r: r[0])
    active_end, active_start, active_name = -1, -1, ""
    for start, end, name in ordered:
        if start < active_end:
            if (active_start, start) not in allowlist:
                violations.append(
                    f"0x{start:x} {name} starts inside 0x{active_start:x} {active_name} "
                    f"(ends 0x{active_end:x}); not in {{'outer:inner'}} overlap allowlist"
                )
        if end > active_end:
            active_end, active_start, active_name = end, start, name
    return violations


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    symbols_path = resolve_repo_path(repo_root, args.symbols_csv)
    if not symbols_path.is_file():
        print(f"Missing symbols file: {symbols_path}", file=sys.stderr)
        return 1

    violations = check_file(symbols_path, args.max_errors)
    if violations:
        print("symbols.csv integrity check failed:")
        for v in violations:
            print(f"  - {v}")
        return 1

    allowlist = read_overlap_allowlist(resolve_repo_path(repo_root, args.overlap_allowlist))
    ranges = load_function_ranges(read_pipe_rows(symbols_path))
    overlap_violations = check_function_overlaps(ranges, allowlist)
    if overlap_violations:
        print("symbols.csv integrity check failed:")
        for v in overlap_violations:
            print(f"  - {v}")
        return 1

    print(f"symbols.csv integrity check passed ({symbols_path}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
