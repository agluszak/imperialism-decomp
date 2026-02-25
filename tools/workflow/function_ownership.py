#!/usr/bin/env python3
"""Shared helpers for function ownership and override config files."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import normalize_repo_relative_path


DEFAULT_FUNCTION_OWNERSHIP_CSV = "config/function_ownership.csv"
DEFAULT_NAME_OVERRIDES_CSV = "config/function_name_overrides.csv"
LEGACY_NAME_OVERRIDES_CSV = "config/name_overrides.csv"
FUNCTION_MARKER_RE_TEMPLATE = (
    r"//\s*(?:FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*{target}\s+"
    r"(?:0x)?([0-9a-fA-F]+)"
)
MANUAL_OVERRIDE_RE_TEMPLATE = (
    r"//\s*MANUAL_OVERRIDE_ADDR\s+{target}\s+"
    r"(?:0x)?([0-9a-fA-F]+)"
)


@dataclass(frozen=True)
class FunctionOwnership:
    address: int
    target_cpp: str
    ownership: str = "manual"
    note: str = ""


def function_marker_regex(target: str) -> re.Pattern[str]:
    return re.compile(FUNCTION_MARKER_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE)


def manual_override_regex(target: str) -> re.Pattern[str]:
    return re.compile(MANUAL_OVERRIDE_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE)


def resolve_name_overrides_path(repo_root: Path, requested_path: str | Path | None) -> Path:
    raw = str(requested_path or DEFAULT_NAME_OVERRIDES_CSV)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = (repo_root / candidate).resolve()

    canonical = (repo_root / DEFAULT_NAME_OVERRIDES_CSV).resolve()
    legacy = (repo_root / LEGACY_NAME_OVERRIDES_CSV).resolve()
    if candidate == canonical and not canonical.is_file() and legacy.is_file():
        return legacy
    return candidate


def load_function_ownership(path: Path) -> dict[int, FunctionOwnership]:
    if not path.is_file():
        return {}

    rows: dict[int, FunctionOwnership] = {}
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        target_cpp = (row.get("target_cpp") or "").strip()
        if not addr_text or not target_cpp:
            continue
        try:
            addr = parse_hex_address(addr_text)
        except ValueError:
            continue
        ownership = (row.get("ownership") or "").strip() or "manual"
        note = (row.get("note") or "").strip()
        rows[addr] = FunctionOwnership(
            address=addr,
            target_cpp=target_cpp,
            ownership=ownership,
            note=note,
        )
    return rows


def write_function_ownership(path: Path, entries: dict[int, FunctionOwnership]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(
            fd,
            fieldnames=["address", "target_cpp", "ownership", "note"],
            delimiter="|",
            lineterminator="\n",
        )
        writer.writeheader()
        for addr in sorted(entries):
            row = entries[addr]
            writer.writerow(
                {
                    "address": format(addr, "x"),
                    "target_cpp": row.target_cpp,
                    "ownership": row.ownership,
                    "note": row.note,
                }
            )
