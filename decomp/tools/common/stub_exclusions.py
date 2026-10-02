"""Retained emissions that must not acquire generated source APIs.

This table controls stub generation only. reccmp owns identity and aliases.
"""

from __future__ import annotations

from pathlib import Path

from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file

EXCLUSIONS_CSV = repo_root_from_file(__file__) / "config" / "stub_exclusions.csv"


def load_stub_exclusions(path: Path | None = None) -> tuple[set[int], list[str]]:
    csv_path = path or EXCLUSIONS_CSV
    if not csv_path.is_file():
        return set(), []
    fields, rows = read_pipe_table(csv_path)
    if fields != ["original_address"]:
        return set(), ["expected only original_address column"]
    excluded: set[int] = set()
    errors: list[str] = []
    for lineno, row in enumerate(rows, 2):
        try:
            address = int(row["original_address"], 16)
        except (TypeError, ValueError):
            errors.append(f"line {lineno}: invalid original address")
            continue
        if len(row) != 1:
            errors.append(f"line {lineno}: expected one field")
        elif address in excluded:
            errors.append(f"line {lineno}: duplicate original address {address:#x}")
        else:
            excluded.add(address)
    return excluded, errors
