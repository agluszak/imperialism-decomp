#!/usr/bin/env python3
"""
Rank unresolved FUN_/thunk_FUN_ functions by selected control tags.

Input is detail CSV from extract_control_tag_usage.py.

Usage:
  .venv/bin/python new_scripts/select_control_tag_fun_candidates.py \
    --detail-csv tmp_decomp/batch199b_unresolved_control_tag_detail.csv \
    --out-csv tmp_decomp/batchX_control_tag_fun_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


DEFAULT_TAGS = [
    "yako",  # okay
    "lcnc",  # cncl
    "ecca",  # acce
    "ejer",  # reje
    "tiaw",  # wait
    "enod",  # done
    "txen",  # next
    "kcab",  # back
    "tfel",  # left
    "thgr",  # rght
    "dart",  # trad
    "nart",  # tran
    "aert",  # trea
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--detail-csv", required=True, help="detail CSV from extract_control_tag_usage.py")
    ap.add_argument(
        "--tags",
        default=",".join(DEFAULT_TAGS),
        help="comma-separated tag_le tokens to consider",
    )
    ap.add_argument(
        "--min-distinct-tags",
        type=int,
        default=1,
        help="minimum distinct tags required",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/control_tag_fun_candidates.csv",
        help="output CSV path",
    )
    ap.add_argument(
        "--name-mode",
        choices=["fun_only", "cluster_only", "all_unresolved"],
        default="fun_only",
        help="Which unresolved name families to include",
    )
    args = ap.parse_args()

    detail_csv = Path(args.detail_csv)
    out_csv = Path(args.out_csv)
    selected_tags = {t.strip() for t in args.tags.split(",") if t.strip()}

    if not detail_csv.exists():
        print(f"missing detail csv: {detail_csv}")
        return 1

    # key -> aggregate
    by_func = defaultdict(
        lambda: {
            "function_addr": "",
            "function_name": "",
            "distinct_tags": set(),
            "total_hits": 0,
            "tags_with_hits": defaultdict(int),
        }
    )

    with detail_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            tag = (row.get("tag_le") or "").strip()
            if tag not in selected_tags:
                continue
            fn = (row.get("function_name") or "").strip()
            is_fun = fn.startswith("FUN_") or fn.startswith("thunk_FUN_")
            is_cluster = fn.startswith("Cluster_")
            if args.name_mode == "fun_only" and not is_fun:
                continue
            if args.name_mode == "cluster_only" and not is_cluster:
                continue
            if args.name_mode == "all_unresolved" and not (is_fun or is_cluster):
                continue
            addr = (row.get("function_addr") or "").strip()
            hits = int((row.get("hit_count") or "0").strip() or 0)
            key = addr.lower()
            agg = by_func[key]
            agg["function_addr"] = addr
            agg["function_name"] = fn
            agg["distinct_tags"].add(tag)
            agg["total_hits"] += hits
            agg["tags_with_hits"][tag] += hits

    rows = []
    for agg in by_func.values():
        dcount = len(agg["distinct_tags"])
        if dcount < args.min_distinct_tags:
            continue
        tags_sorted = sorted(agg["distinct_tags"])
        tag_hits_sorted = sorted(
            agg["tags_with_hits"].items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        rows.append(
            {
                "function_addr": agg["function_addr"],
                "function_name": agg["function_name"],
                "distinct_tag_count": str(dcount),
                "total_hits": str(agg["total_hits"]),
                "tags": ",".join(tags_sorted),
                "tag_hits": ";".join(f"{k}:{v}" for k, v in tag_hits_sorted),
            }
        )

    rows.sort(
        key=lambda r: (
            -int(r["distinct_tag_count"]),
            -int(r["total_hits"]),
            r["function_addr"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "function_addr",
                "function_name",
                "distinct_tag_count",
                "total_hits",
                "tags",
                "tag_hits",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for row in rows[:60]:
        print(
            f"{row['function_addr']} {row['function_name']} "
            f"tags={row['tags']} hits={row['total_hits']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
