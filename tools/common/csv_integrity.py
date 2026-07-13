#!/usr/bin/env python3
"""Shared structural-integrity checks for this repo's pipe-delimited config CSVs.

Every consumer of these files reads them with `csv.DictReader`/`read_pipe_rows`,
which both trust line 1 to be the header. That assumption has broken silently
before: a resort once moved `config/symbols.csv`'s header to EOF and broke vtable
resolution for 364/379 vtables with no error anywhere. `check_pipe_csv_structure`
centralizes the fix (header-at-line-1, no duplicate header, every row hex-address
parseable with enough columns, no duplicate address) so each CSV's integrity gate
is a thin wrapper instead of a re-implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence


def check_pipe_csv_structure(
    path: Path,
    base_columns: Sequence[str],
    optional_columns: Sequence[str] = (),
    max_errors: int = 20,
) -> list[str]:
    violations: list[str] = []
    lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    if not lines:
        return [f"{path}: file is empty"]

    header = "|".join(base_columns)
    valid_headers = {header}
    if optional_columns:
        header_with_optional = "|".join(list(base_columns) + list(optional_columns))
        valid_headers.add(header_with_optional)
        expected_desc = f"'{header}' with optional '|{'|'.join(optional_columns)}'"
    else:
        expected_desc = f"'{header}'"

    if lines[0] not in valid_headers:
        violations.append(
            f"line 1: expected the header row ({expected_desc}), got: {lines[0][:80]!r}"
        )

    column_count = len(lines[0].split("|")) if lines[0] in valid_headers else len(base_columns)  # pipe-split-ok: structural validator

    seen: dict[int, int] = {}
    for idx, line in enumerate(lines[1:], start=2):
        if not line.strip():
            violations.append(f"line {idx}: blank line")
            continue
        if line in valid_headers:
            violations.append(f"line {idx}: duplicate header row")
            continue
        parts = line.split("|")  # pipe-split-ok: structural validator
        if len(parts) < len(base_columns):
            violations.append(
                f"line {idx}: only {len(parts)} fields (need >= {len(base_columns)}): {line[:60]!r}"
            )
            continue
        if len(parts) > column_count:
            violations.append(
                f"line {idx}: {len(parts)} fields exceeds header's {column_count}: {line[:60]!r}"
            )
        addr_text = parts[0].strip().lower().removeprefix("0x")
        try:
            addr = int(addr_text, 16)
        except ValueError:
            violations.append(f"line {idx}: unparseable address field: {parts[0]!r}")
            continue
        if addr in seen:
            violations.append(
                f"line {idx}: duplicate address 0x{addr:x} (first at line {seen[addr]})"
            )
        else:
            seen[addr] = idx

        if len(violations) > max_errors:
            violations.append("... (truncated)")
            break

    return violations
