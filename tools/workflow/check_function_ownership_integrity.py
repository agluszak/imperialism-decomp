#!/usr/bin/env python3
"""Structural integrity gate for config/function_ownership.csv.

`function_ownership.py`'s `load_function_ownership` reads this file via
`read_pipe_rows` (`csv.DictReader`), which trusts line 1 to be the header, exactly
the assumption that once silently broke `config/symbols.csv` (a resort moved its
header to EOF and broke vtable resolution for 364/379 vtables with no error
anywhere — see `check_symbols_integrity.py`). This file is also the one most
directly implicated in the repeated "curated suppression note silently pruned"
incident: `load_function_ownership`'s `rows[addr] = entry` loop lets a duplicate
`address` row silently shadow an earlier one (including its `note`) with no warning.

Deliberately NOT checked: `ownership`/`note` value vocabulary — that drifts into
heuristic territory; this gate stays purely structural.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.common.csv_integrity import check_pipe_csv_structure
from tools.common.repo import repo_root_from_file, resolve_repo_path

BASE_COLUMNS = ["address", "target_cpp", "ownership", "note"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ownership-csv",
        default="config/function_ownership.csv",
        help="Pipe-delimited function ownership table to verify.",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=20,
        help="Stop printing after this many violations (still fails).",
    )
    return parser.parse_args()


def check_file(path: Path, max_errors: int) -> list[str]:
    return check_pipe_csv_structure(path, BASE_COLUMNS, max_errors=max_errors)


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    ownership_path = resolve_repo_path(repo_root, args.ownership_csv)
    if not ownership_path.is_file():
        print(f"Missing ownership file: {ownership_path}", file=sys.stderr)
        return 1

    violations = check_file(ownership_path, args.max_errors)
    if violations:
        print("function_ownership.csv integrity check failed:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print(f"function_ownership.csv integrity check passed ({ownership_path}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
