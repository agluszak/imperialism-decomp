#!/usr/bin/env python3
"""Gate: synthetic symbol names in source comments must match config/original_entities.csv.

A ``// SYNTHETIC: IMPERIALISM 0x...`` marker is immediately followed by a
``// Name`` comment giving the symbol the marker claims. This gate confirms
the next line is such a comment and that the name matches the row in
config/original_entities.csv for that address. Drift here means reccmp's
``ScalarDeletingDestructor`` (or other synthetic) entity is being claimed by a
marker that does not match the symbol the address resolves to, which is
confusing for both tooling and humans.

This is a check-only gate; it never edits files. Renames are done by
``tools.workflow.correct_scalar_dtors`` (or by hand).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

SYNTHETIC_MARKER_RE = re.compile(
    r"^\s*//\s*SYNTHETIC\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)

# A comment line like '// Class::`scalar deleting destructor'' or '// Name'.
COMMENT_LINE_RE = re.compile(r"^\s*//\s*(?P<name>\S.*?)\s*$")


def canonical_addr(value: str) -> str:
    """Lowercase, strip 0x, and strip leading zeros so '00591ec0' == '591ec0'."""
    raw = (value or "").strip().lower().removeprefix("0x")
    if not raw:
        return ""
    return f"{int(raw, 16):x}"


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
        help="Files or directories to scan.",
    )
    return parser.parse_args()


def load_symbols(csv_path: Path) -> dict[str, str]:
    symbols: dict[str, str] = {}
    if not csv_path.exists():
        return symbols
    _fieldnames, rows = read_pipe_table(csv_path)
    for row in rows:
        addr = canonical_addr(row.get("address") or "")
        name = (row.get("name") or "").strip()
        if addr and name:
            symbols[addr] = name
    return symbols


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    symbols = load_symbols(Path(args.symbols_csv))

    violations: list[str] = []
    synthetic_count = 0

    for path in iter_files(args.paths):
        rel = normalize_repo_relative_path(path, repo_root)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, line in enumerate(lines):
            match = SYNTHETIC_MARKER_RE.match(line)
            if match is None:
                continue
            synthetic_count += 1
            offset_raw = match.group("offset")
            offset_norm = canonical_addr(offset_raw)

            if idx + 1 >= len(lines):
                violations.append(
                    f"{rel}:{idx + 1}: SYNTHETIC marker at end of file, missing comment name."
                )
                continue
            cmt_match = COMMENT_LINE_RE.match(lines[idx + 1])
            if cmt_match is None:
                violations.append(
                    f"{rel}:{idx + 1}: SYNTHETIC marker must be immediately followed by a comment line showing the name."
                )
                continue
            comment_name = cmt_match.group("name").strip()
            expected_name = symbols.get(offset_norm)
            if expected_name is None:
                violations.append(
                    f"{rel}:{idx + 1}: Address 0x{offset_norm} has no entry in config/original_entities.csv"
                )
            elif comment_name != expected_name:
                violations.append(
                    f"{rel}:{idx + 1}: Synthetic name mismatch. Source: '{comment_name}', symbols.csv: '{expected_name}'"
                )

    print(f"Scanned {synthetic_count} SYNTHETIC markers.")
    if violations:
        print("Synthetic name validation failed:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("Synthetic name validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
