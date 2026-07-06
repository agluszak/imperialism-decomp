#!/usr/bin/env python3
"""Shared loaders for config/symbols.csv and config/function_ownership.csv.

Half a dozen tools re-implemented "read symbols.csv into a dict" with slightly
different shapes (name→addr, addr→name, functions-only, with/without sizes).
These are the canonical copies; all skip unparsable address rows the same way.
"""

from __future__ import annotations

from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows


def names_by_address(repo_root: Path) -> dict[int, str]:
    """address -> name for every symbols.csv row (all types)."""
    out: dict[int, str] = {}
    for row in read_pipe_rows(repo_root / "config" / "symbols.csv"):
        try:
            out[int(row["address"], 16)] = row.get("name") or ""
        except ValueError:
            continue
    return out


def functions_by_name(repo_root: Path) -> dict[str, tuple[int, int]]:
    """name -> (address, size) for function rows (first row wins on dup names)."""
    out: dict[str, tuple[int, int]] = {}
    for row in read_pipe_rows(repo_root / "config" / "symbols.csv"):
        if row.get("type") != "function":
            continue
        try:
            addr = int(row["address"], 16)
            size = int(row.get("size") or 0)
        except ValueError:
            continue
        out.setdefault(row["name"], (addr, size))
    return out


def ownership_by_address(repo_root: Path) -> dict[int, str]:
    """address -> ownership ('manual'/'library'/'stub') from function_ownership.csv."""
    out: dict[int, str] = {}
    for row in read_pipe_rows(repo_root / "config" / "function_ownership.csv"):
        try:
            out[int(row["address"], 16)] = row.get("ownership") or ""
        except ValueError:
            continue
    return out
