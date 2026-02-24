#!/usr/bin/env python3
"""Annotate manual functions that originated as __thiscall in symbols.csv.

This script inserts:
  // ORIG_CALLCONV: __thiscall
inside function bodies for address-annotated functions in source files.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

FUNCTION_RE = re.compile(r"//\s*FUNCTION:\s*IMPERIALISM\s+0x([0-9A-Fa-f]+)")
ORIG_MARKER = "ORIG_CALLCONV: __thiscall"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--symbols-csv",
        default="config/symbols.csv",
        help="Path to exported symbols CSV (pipe-delimited).",
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Source files to annotate (usually touched src/game/*.cpp files).",
    )
    return parser.parse_args()


def load_thiscall_addresses(symbols_csv: Path) -> set[int]:
    with symbols_csv.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        result: set[int] = set()
        for row in reader:
            if (row.get("type") or "").strip().lower() != "function":
                continue
            prototype = (row.get("prototype") or "").strip()
            if "__thiscall" not in prototype:
                continue
            address_text = (row.get("address") or "").strip()
            if not address_text:
                continue
            result.add(int(address_text, 16))
        return result


def annotate_segment(segment: str) -> tuple[str, bool]:
    brace_idx = segment.find("{")
    if brace_idx < 0:
        return segment, False

    lookahead = segment[brace_idx : min(len(segment), brace_idx + 320)]
    if ORIG_MARKER in lookahead:
        return segment, False

    insert_idx = brace_idx + 1
    after = segment[insert_idx:]
    indent_match = re.match(r"\n([ \t]*)", after)
    indent = indent_match.group(1) if indent_match else "  "
    comment = "\n{}// {}".format(indent, ORIG_MARKER)
    return segment[:insert_idx] + comment + segment[insert_idx:], True


def annotate_file(path: Path, thiscall_addrs: set[int]) -> int:
    text = path.read_text(encoding="utf-8", errors="ignore")
    matches = list(FUNCTION_RE.finditer(text))
    if not matches:
        return 0

    chunks: list[str] = []
    cursor = 0
    insertions = 0

    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        chunks.append(text[cursor:start])

        segment = text[start:end]
        addr = int(match.group(1), 16)
        if addr in thiscall_addrs:
            segment, changed = annotate_segment(segment)
            if changed:
                insertions += 1
        chunks.append(segment)
        cursor = end

    chunks.append(text[cursor:])
    if insertions > 0:
        path.write_text("".join(chunks), encoding="utf-8")
    return insertions


def main() -> int:
    args = parse_args()
    symbols_csv = Path(args.symbols_csv)
    if not symbols_csv.is_file():
        raise SystemExit("Missing symbols CSV: {}".format(symbols_csv))

    thiscall_addrs = load_thiscall_addresses(symbols_csv)
    total_insertions = 0

    for file_arg in args.files:
        path = Path(file_arg)
        if not path.is_file():
            raise SystemExit("Missing file: {}".format(path))
        inserted = annotate_file(path, thiscall_addrs)
        total_insertions += inserted
        print("{}: +{} marker(s)".format(path, inserted))

    print("Total markers inserted: {}".format(total_insertions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
