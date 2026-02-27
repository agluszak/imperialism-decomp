#!/usr/bin/env python3
"""
Build conservative rename candidates from Function ID analyzer bookmark export.

Input CSV format:
  address,function_name,bookmark_category,bookmark_comment

Output CSV columns:
  address,new_name,raw_match_name,source

Usage:
  .venv/bin/python new_scripts/build_fid_single_match_candidates.py \
    tmp_decomp/batch327_imperialism_fid_bookmarks.csv \
    tmp_decomp/batch327_fid_single_match_candidates.csv
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path


SINGLE_MATCH_RE = re.compile(r"Single Match,\s*(.*)$")

# Aggressive noise filters: these names produce weak semantics or invalid C identifiers.
BLOCK_SUBSTR = (
    "scalar_deleting_destructor",
    "vector_deleting_destructor",
    "operator",
    "FID_conflict:",
    "??",
)

BLOCK_EXACT = {
    "Create",
    "Attach",
    "Detach",
    "Read",
    "Write",
    "Run",
    "Open",
    "Close",
    "Load",
    "Remove",
    "Release",
    "Lookup",
    "Format",
    "CString",
    "CDialog",
    "CWnd",
    "CTime",
    "CFile",
    "CException",
    "AfxMessageBox",
    "OnCmdMsg",
    "OnChildNotify",
}


def to_identifier(raw: str) -> str:
    raw = raw.strip().strip("`")
    raw = raw.replace("::", "_")
    raw = re.sub(r"[^0-9A-Za-z_]", "_", raw)
    raw = re.sub(r"_+", "_", raw).strip("_")
    if not raw:
        return ""
    if raw[0].isdigit():
        raw = "Lib_" + raw
    return raw


def should_keep(raw: str) -> bool:
    if not raw:
        return False
    if raw.startswith("~"):
        return False
    if raw in BLOCK_EXACT:
        return False
    for token in BLOCK_SUBSTR:
        if token in raw:
            return False
    return True


def build(in_csv: Path, out_csv: Path) -> tuple[int, int]:
    rows_in = 0
    rows_out = 0
    seen_addresses: set[str] = set()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    used_names: set[str] = set()
    with in_csv.open(newline="", encoding="utf-8") as fin, out_csv.open(
        "w", newline="", encoding="utf-8"
    ) as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(
            fout, fieldnames=["address", "new_name", "raw_match_name", "source"]
        )
        writer.writeheader()
        for row in reader:
            rows_in += 1
            comment = (row.get("bookmark_comment") or "").strip()
            m = SINGLE_MATCH_RE.search(comment)
            if not m:
                continue
            raw_name = m.group(1).strip()
            if not should_keep(raw_name):
                continue

            addr = (row.get("address") or "").strip()
            if not addr or addr in seen_addresses:
                continue
            new_name = to_identifier(raw_name)
            if not new_name or len(new_name) < 3:
                continue
            if new_name in used_names:
                new_name = f"{new_name}_{addr.lower().lstrip('0x')}"
            used_names.add(new_name)

            writer.writerow(
                {
                    "address": f"0x{addr.lower().lstrip('0x')}",
                    "new_name": new_name,
                    "raw_match_name": raw_name,
                    "source": "FID_single_match_phase1_nodebug",
                }
            )
            seen_addresses.add(addr)
            rows_out += 1
    return rows_in, rows_out


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: build_fid_single_match_candidates.py <in_csv> <out_csv>",
            file=sys.stderr,
        )
        return 2
    in_csv = Path(sys.argv[1])
    out_csv = Path(sys.argv[2])
    rows_in, rows_out = build(in_csv, out_csv)
    print(f"[in] {in_csv} rows={rows_in}")
    print(f"[out] {out_csv} candidates={rows_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
