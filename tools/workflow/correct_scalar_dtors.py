#!/usr/bin/env python3
"""Normalize scalar-deleting-destructor rows in config/original_entities.csv and source comments.

MSVC500 mangles the compiler-generated scalar deleting destructor as
``Class::`scalar deleting destructor'``. Ghidra imports frequently lose the
backtick/quote framing and land as variations like
``Class::'scalar_deleting_destructor'``, ``Class::`scalar_deleting_destructor'``,
or ``Class::'scalar deleting destructor'``. This script canonicalizes all of
them to the MSVC form and pairs each row with the conventional
``undefined ScalarDeletingDestructor()`` prototype, then mirrors the same name
into the matching ``// SYNTHETIC:`` comment line in source files.

This is a one-shot/periodic migration helper, not a gate. The mechanical
check that names are consistent lives in ``check_synthetic_names`` (run via
``just synthetic-gate``).
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from tools.common.file_scan import iter_files
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

# Matches every observed spelling of the scalar deleting destructor name:
#   Class::'scalar_deleting_destructor'
#   Class::`scalar_deleting_destructor'
#   Class::'scalar deleting destructor'
#   Class::`scalar deleting destructor'
#   (and mixed backtick/quote pairs from copy-paste)
# Quote/underscore variations only -- the class name and the literal
# "scalar deleting destructor" wording must be present.
SYMBOL_NAME_RE = re.compile(
    r"^(?P<cls>[A-Za-z0-9_]+)::(?P<qopen>['`])scalar[_ ]deleting[_ ]destructor(?P<qclose>['`])$"
)

SOURCE_COMMENT_RE = re.compile(
    r"^(?P<indent>\s*//\s*)(?P<cls>[A-Za-z0-9_]+)::(?P<qopen>['`])scalar[_ ]deleting[_ ]destructor(?P<qclose>['`])$"
)

CANONICAL_PROTOTYPE = "undefined ScalarDeletingDestructor()"


def canonical_name(class_name: str) -> str:
    return f"{class_name}::`scalar deleting destructor'"


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--symbols-csv",
        default=str(repo_root / "config" / "original_entities.csv"),
        help="Path to symbols.csv (pipe-delimited).",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["src", "include"],
        help="Files or directories to scan for SYNTHETIC comments.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change, modify nothing.",
    )
    return parser.parse_args()


def fix_symbols_csv(csv_path: Path, dry_run: bool) -> int:
    fieldnames, rows = read_pipe_table(csv_path)
    changes = 0
    for row in rows:
        name = (row.get("name") or "").strip()
        match = SYMBOL_NAME_RE.match(name)
        if not match:
            continue
        new_name = canonical_name(match.group("cls"))
        new_proto = CANONICAL_PROTOTYPE
        changed = False
        if name != new_name:
            row["name"] = new_name
            changed = True
        if (row.get("prototype") or "").strip() != new_proto:
            row["prototype"] = new_proto
            changed = True
        if changed:
            changes += 1

    if changes == 0:
        print(f"No scalar deleting destructor renames needed in {csv_path}.")
        return 0

    if dry_run:
        print(f"[dry-run] Would update {changes} row(s) in {csv_path}.")
        return 0

    with csv_path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Updated {changes} row(s) in {csv_path}.")
    return changes


def fix_source_files(paths: list[str], dry_run: bool) -> int:
    changed_files = 0
    for path in iter_files(paths):
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        modified = False
        for idx, line in enumerate(lines):
            match = SOURCE_COMMENT_RE.match(line)
            if not match:
                continue
            new_line = f"{match.group('indent')}{canonical_name(match.group('cls'))}"
            if new_line != line:
                lines[idx] = new_line
                modified = True
        if not modified:
            continue
        changed_files += 1
        rel = normalize_repo_relative_path(path, repo_root_from_file(__file__))
        if dry_run:
            print(f"[dry-run] Would rewrite SYNTHETIC comments in {rel}")
            continue
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Updated SYNTHETIC comments in {rel}")
    if changed_files == 0:
        print("No source comment renames needed.")
    return changed_files


def main() -> int:
    args = parse_args()
    fix_symbols_csv(Path(args.symbols_csv), args.dry_run)
    fix_source_files(args.paths, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
