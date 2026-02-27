#!/usr/bin/env python3
"""
Filter a global-state atlas CSV down to gameplay-centric globals.

Usage:
  .venv/bin/python new_scripts/filter_global_state_atlas_gameplay.py \
    --in-csv tmp_decomp/batch373_global_state_atlas.csv \
    --out-csv tmp_decomp/batch373_global_state_atlas_gameplay.csv \
    --out-json tmp_decomp/batch373_global_state_atlas_gameplay.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument(
        "--name-regex",
        default=(
            r"(Nation|Diplomacy|Map|Turn|Order|Terrain|Interaction|EventQueue|"
            r"GameFlow|PortZone|Strategic|Civilian|Navy|Army)"
        ),
    )
    ap.add_argument("--top-k", type=int, default=120)
    args = ap.parse_args()

    in_csv = Path(args.in_csv).resolve()
    out_csv = Path(args.out_csv).resolve()
    out_json = Path(args.out_json).resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    if not in_csv.exists():
        print(f"[error] missing input: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    name_re = re.compile(args.name_regex, re.IGNORECASE)
    kept = [r for r in rows if name_re.search((r.get("name") or ""))]
    kept.sort(
        key=lambda r: (
            -int(r.get("code_refs") or 0),
            -int(r.get("write_refs") or 0),
            r.get("address") or "",
        )
    )
    if args.top_k > 0:
        kept = kept[: args.top_k]

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
        if rows:
            w.writeheader()
            w.writerows(kept)

    summary = {
        "input_rows": len(rows),
        "kept_rows": len(kept),
        "name_regex": args.name_regex,
        "top_by_writes": [
            {
                "address": r.get("address", ""),
                "name": r.get("name", ""),
                "write_refs": int(r.get("write_refs") or 0),
                "top_writers": r.get("top_writers", ""),
            }
            for r in sorted(kept, key=lambda x: -int(x.get("write_refs") or 0))[:30]
        ],
        "top_by_reads": [
            {
                "address": r.get("address", ""),
                "name": r.get("name", ""),
                "read_refs": int(r.get("read_refs") or 0),
                "top_readers": r.get("top_readers", ""),
            }
            for r in sorted(kept, key=lambda x: -int(x.get("read_refs") or 0))[:30]
        ],
    }
    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[saved] {out_csv} rows={len(kept)}")
    print(f"[saved] {out_json}")
    for r in summary["top_by_writes"][:10]:
        print(
            f"[gameplay-write-hot] {r['address']} {r['name']} "
            f"write_refs={r['write_refs']} writers={r['top_writers']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

