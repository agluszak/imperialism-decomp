#!/usr/bin/env python3
"""Shared parser for function name/prototype override CSV."""

from __future__ import annotations

from pathlib import Path

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows


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
