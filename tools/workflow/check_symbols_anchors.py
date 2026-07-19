#!/usr/bin/env python3
"""Fail when config/original_entities.csv drifts off known-good anchor rows."""

from __future__ import annotations

import argparse
import sys

from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import repo_root_from_file, resolve_repo_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--symbols-csv",
        default="config/original_entities.csv",
        help="Pipe-delimited symbols table to verify.",
    )
    parser.add_argument(
        "--anchors-csv",
        default="config/symbols_anchor_checks.csv",
        help="Pipe-delimited address|name rows that must match exactly.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    symbols_path = resolve_repo_path(repo_root, args.symbols_csv)
    anchors_path = resolve_repo_path(repo_root, args.anchors_csv)

    if not symbols_path.is_file():
        print(f"Missing symbols file: {symbols_path}", file=sys.stderr)
        return 1
    if not anchors_path.is_file():
        print(f"Missing anchors file: {anchors_path}", file=sys.stderr)
        return 1

    _, symbol_rows = read_pipe_table(symbols_path)
    by_addr = {
        int((row.get("address") or "").strip(), 16): row
        for row in symbol_rows
        if (row.get("address") or "").strip()
    }

    _, anchor_rows = read_pipe_table(anchors_path)
    failures: list[str] = []
    for anchor in anchor_rows:
        addr_text = (anchor.get("address") or "").strip()
        expected = (anchor.get("name") or "").strip()
        if not addr_text or not expected:
            continue
        addr = int(addr_text, 16)
        row = by_addr.get(addr)
        if row is None:
            failures.append(f"0x{addr:08X}: missing row (expected {expected!r})")
            continue
        actual = (row.get("name") or "").strip()
        if actual != expected:
            failures.append(f"0x{addr:08X}: {actual!r} != {expected!r}")

    if failures:
        print("symbols anchor gate failed:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1

    print(f"symbols anchor gate passed ({len(anchor_rows)} anchors).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
