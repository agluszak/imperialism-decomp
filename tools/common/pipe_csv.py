#!/usr/bin/env python3
"""Helpers for pipe-delimited CSV files used by tooling."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Callable


def normalize_hex(value: str) -> str:
    return value.strip().lower().removeprefix("0x")


def header_column_indices(header_line: str, *columns: str) -> tuple[int, ...]:
    """Resolve column positions from a pipe-CSV header line.

    For line-preserving rewriters that must keep unrelated rows byte-identical
    (so they cannot round-trip through DictReader/DictWriter). Never hardcode
    column indices — a schema change silently breaks them (the prune_ilt_thunks
    / gen_library_annotations parts[3]-vs-parts[4] bug class).
    """
    names = [name.strip() for name in header_line.rstrip("\n").split("|")]  # pipe-split-ok
    out = []
    for column in columns:
        try:
            out.append(names.index(column))
        except ValueError:
            raise SystemExit(f"Column '{column}' not found in header: {names}")
    return tuple(out)


def read_pipe_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        return list(reader)


def read_pipe_table(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    return fieldnames, rows


def read_pipe_map(
    path: Path,
    key_column: str,
    value_column: str,
    normalize_key: Callable[[str], str] | None = None,
    normalize_value: Callable[[str], str] | None = None,
) -> dict[str, str]:
    if not path.exists():
        return {}

    key_norm = normalize_key or (lambda x: x)
    value_norm = normalize_value or (lambda x: x)

    out: dict[str, str] = {}
    for row in read_pipe_rows(path):
        key = key_norm((row.get(key_column) or "").strip())
        value = value_norm((row.get(value_column) or "").strip())
        if not key or not value:
            continue
        out[key] = value
    return out
