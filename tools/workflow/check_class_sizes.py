#!/usr/bin/env python3
"""Cross-check modeled class sizes against the RTTI oracle.

The binary's MFC CRuntimeClass descriptors carry the true `m_nObjectSize` for every
game class (config/rtti_class_oracle.csv, refresh with `just rtti-oracle --csv`).
This check joins them against every `ASSERT_SIZE(Class, 0xNN)` in the source tree
and reports:
  - MISMATCH: we assert a size the compiler's own RTTI contradicts (layout bug);
  - UNASSERTED: the oracle knows the class but no ASSERT_SIZE pins our model.

Report-only by default (exit 0). Pass --strict to fail on mismatches (for use as a
gate once the report is clean).
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file

ASSERT_RE = re.compile(r"ASSERT_SIZE\(\s*(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
MFC_DESCRIPTOR_RANGE = range(0x66F000, 0x675000)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle-csv", default="config/rtti_class_oracle.csv")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero on size mismatches.")
    parser.add_argument("--show-unasserted", action="store_true",
                        help="Also list oracle classes with no ASSERT_SIZE.")
    return parser.parse_args()


def collect_asserts(repo_root: Path) -> dict[str, tuple[int, str]]:
    found: dict[str, tuple[int, str]] = {}
    for base in ("include", "src"):
        for path in (repo_root / base).rglob("*.*"):
            if path.suffix not in (".h", ".hpp", ".cpp", ".cc"):
                continue
            posix = path.as_posix()
            if "/autogen/" in posix or "/ghidra_autogen/" in posix:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in ASSERT_RE.finditer(text):
                name = m.group(1)
                size = int(m.group(2), 0)
                found[name] = (size, posix)
    return found


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    oracle_path = repo_root / args.oracle_csv
    if not oracle_path.is_file():
        print(f"Missing oracle CSV: {oracle_path} (run `just rtti-oracle --csv`)",
              file=sys.stderr)
        return 1

    oracle: dict[str, int] = {}
    for row in csv.DictReader(oracle_path.open()):
        if int(row["descriptor"], 16) in MFC_DESCRIPTOR_RANGE:
            continue
        oracle[row["name"]] = int(row["object_size"], 16)

    asserts = collect_asserts(repo_root)

    mismatches: list[str] = []
    matched = 0
    for name, (size, path) in sorted(asserts.items()):
        true_size = oracle.get(name)
        if true_size is None:
            continue  # not an RTTI class (view structs, PODs, etc.)
        if size != true_size:
            mismatches.append(
                f"  MISMATCH {name}: ASSERT_SIZE 0x{size:x} vs RTTI m_nObjectSize "
                f"0x{true_size:x}  ({path})"
            )
        else:
            matched += 1

    unasserted = sorted(name for name in oracle if name not in asserts)

    print(f"oracle classes: {len(oracle)}  asserted+verified: {matched}  "
          f"mismatched: {len(mismatches)}  unasserted: {len(unasserted)}")
    for line in mismatches:
        print(line)
    if args.show_unasserted:
        for name in unasserted:
            print(f"  UNASSERTED {name} (RTTI size 0x{oracle[name]:x})")

    if args.strict and mismatches:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
