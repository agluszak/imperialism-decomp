#!/usr/bin/env python3
"""Shared parser/locator for the function name/prototype override CSV.

`config/function_name_overrides.csv` is the single curated name authority:
stubgen, sync_exports, and push_names_to_ghidra all resolve the file through
`resolve_name_overrides_path` and parse it through `parse_name_overrides`.
"""

from __future__ import annotations

from pathlib import Path

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows

DEFAULT_NAME_OVERRIDES_CSV = "config/function_name_overrides.csv"


def resolve_name_overrides_path(repo_root: Path, requested_path: str | Path | None) -> Path:
    candidate = Path(str(requested_path or DEFAULT_NAME_OVERRIDES_CSV))
    if not candidate.is_absolute():
        candidate = (repo_root / candidate).resolve()
    return candidate


def sanitize_override_field(text: str) -> str:
    return " ".join(text.replace("|", " ").split())


def parse_name_overrides(path: Path) -> dict[int, tuple[str, str]]:
    if not path.is_file():
        return {}

    rows: dict[int, tuple[str, str]] = {}
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        address = parse_hex_address(addr_text)
        name = sanitize_override_field((row.get("name") or "").strip())
        prototype = sanitize_override_field((row.get("prototype") or "").strip())
        rows[address] = (name, prototype)
    return rows
