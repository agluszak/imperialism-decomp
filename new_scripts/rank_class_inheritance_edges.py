#!/usr/bin/env python3
"""
Aggregate class inheritance edge evidence into pair-level ranked summary.

Input:
  CSV from generate_class_inheritance_edges.py

Output columns:
  base_class,derived_class,total_support,high_support,medium_support,low_support,evidence_kinds,sample_functions

Usage:
  .venv/bin/python new_scripts/rank_class_inheritance_edges.py \
    --in-csv tmp_decomp/class_inheritance_edges_batch358.csv \
    --out-csv tmp_decomp/class_inheritance_edges_ranked_batch358.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="Input edge evidence CSV")
    ap.add_argument("--out-csv", required=True, help="Output ranked pair CSV")
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    if not in_csv.exists():
        print(f"[error] missing input: {in_csv}")
        return 1
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "base_class",
                    "derived_class",
                    "total_support",
                    "high_support",
                    "medium_support",
                    "low_support",
                    "evidence_kinds",
                    "sample_functions",
                ],
            )
            w.writeheader()
        print(f"[done] empty input -> {out_csv}")
        return 0

    agg = defaultdict(
        lambda: {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "kinds": set(),
            "funcs": [],
        }
    )
    for r in rows:
        key = (r["base_class"], r["derived_class"])
        a = agg[key]
        a["total"] += 1
        conf = (r.get("confidence") or "").strip().lower()
        if conf == "high":
            a["high"] += 1
        elif conf == "medium":
            a["medium"] += 1
        else:
            a["low"] += 1
        a["kinds"].add(r.get("evidence_kind", ""))
        fn = f"{r.get('function_addr','')}:{r.get('function_name','')}"
        if fn not in a["funcs"]:
            a["funcs"].append(fn)

    out_rows = []
    for (base, derived), a in agg.items():
        out_rows.append(
            {
                "base_class": base,
                "derived_class": derived,
                "total_support": str(a["total"]),
                "high_support": str(a["high"]),
                "medium_support": str(a["medium"]),
                "low_support": str(a["low"]),
                "evidence_kinds": ",".join(sorted(k for k in a["kinds"] if k)),
                "sample_functions": ";".join(a["funcs"][:8]),
            }
        )

    out_rows.sort(
        key=lambda r: (
            -int(r["high_support"]),
            -int(r["total_support"]),
            r["base_class"],
            r["derived_class"],
        )
    )

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "base_class",
                "derived_class",
                "total_support",
                "high_support",
                "medium_support",
                "low_support",
                "evidence_kinds",
                "sample_functions",
            ],
        )
        w.writeheader()
        w.writerows(out_rows)

    print(f"[done] in_rows={len(rows)} out_pairs={len(out_rows)} -> {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

