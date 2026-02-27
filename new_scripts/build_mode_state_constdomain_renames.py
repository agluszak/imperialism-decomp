#!/usr/bin/env python3
"""
Build conservative mode/state hint renames from constant-domain candidate CSV.

Input: CSV from generate_constant_domain_candidates.py
Output: address,new_name,comment

Rules:
  - function_name must be FUN_*
  - hit_count >= --min-hits
  - unique_ids >= --min-ids
  - infer exactly one lane among Tactical / TurnState / OrderState

Usage:
  .venv/bin/python new_scripts/build_mode_state_constdomain_renames.py \
    --in-csv tmp_decomp/batch361_constant_domain_candidates_mode_state.csv \
    --out-csv tmp_decomp/batch361_mode_state_constdomain_renames.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

TACTICAL_IDS = {28, 29, 30, 31, 33, 34, 36}
ORDER_IDS = {8, 9, 10, 11, 18, 26, 27}


def parse_ids(raw: str) -> set[int]:
    out = set()
    for tok in (raw or "").split(","):
        t = tok.strip()
        if not t:
            continue
        try:
            out.add(int(t))
        except Exception:
            pass
    return out


def infer_lane(function_name: str, ids: set[int]) -> str | None:
    lanes = set()
    lname = function_name.lower()
    if ids & TACTICAL_IDS:
        lanes.add("Tactical")
    if ids & ORDER_IDS or "order" in lname:
        lanes.add("OrderState")
    if "turnstate" in lname or "turnevent" in lname or "turn" in lname:
        lanes.add("TurnState")
    if len(lanes) != 1:
        return None
    return next(iter(lanes))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--min-hits", type=int, default=6)
    ap.add_argument("--min-ids", type=int, default=3)
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    if not in_csv.exists():
        print(f"[error] missing input: {in_csv}")
        return 1
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    out = []
    for r in rows:
        fname = (r.get("function_name") or "").strip()
        if not fname.startswith("FUN_"):
            continue
        hits = int((r.get("hit_count") or "0").strip() or 0)
        uniq = int((r.get("unique_ids") or "0").strip() or 0)
        if hits < args.min_hits or uniq < args.min_ids:
            continue
        ids = parse_ids(r.get("matched_ids") or "")
        lane = infer_lane(fname, ids)
        if lane is None:
            continue
        addr = (r.get("address") or "").strip()
        if not addr:
            continue
        hexpart = addr.lower().replace("0x", "")
        out.append(
            {
                "address": addr if addr.startswith("0x") else f"0x{addr}",
                "new_name": f"Cluster_{lane}ConstDomainHint_{hexpart}",
                "comment": (
                    f"[ConstDomain] {lane} lane hint from matched IDs: "
                    f"{r.get('matched_ids','')}"
                ),
            }
        )

    # Deduplicate by address.
    dedup = {}
    for r in out:
        dedup[r["address"]] = r
    out_rows = [dedup[k] for k in sorted(dedup.keys())]

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(out_rows)

    print(f"[done] in_rows={len(rows)} out_rows={len(out_rows)} -> {out_csv}")
    for r in out_rows[:120]:
        print(f"{r['address']},{r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

