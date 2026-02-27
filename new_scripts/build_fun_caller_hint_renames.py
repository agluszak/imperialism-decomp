#!/usr/bin/env python3
"""
Build safe hint-style function rename CSV from FUN_* caller-candidate CSV.

Input format (from generate_fun_caller_candidates.py):
  caller_addr,caller_name,total_hits,unique_callees,callee_names

Output format (for apply_function_renames_csv.py):
  address,new_name,comment

Usage:
  .venv/bin/python new_scripts/build_fun_caller_hint_renames.py \
    --in-csv tmp_decomp/batch72_fun_callers_map_actions.csv \
    --out-csv tmp_decomp/batch73_gameplay_hint_renames.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


DOMAIN_KEYWORDS = [
    ("Tactical", re.compile(r"tactical|actionclass|cursormodeprofile", re.IGNORECASE)),
    ("MapTile", re.compile(r"hex|tile|neighbor|direction|movement|path|wrap", re.IGNORECASE)),
    ("Civilian", re.compile(r"civilian|workorder|improve|mine|farm|forester|prospect", re.IGNORECASE)),
    ("ArmyNavy", re.compile(r"army|navy|taskforce|war|battle", re.IGNORECASE)),
    ("TurnState", re.compile(r"turnstate|turnevent|turn", re.IGNORECASE)),
    ("NationState", re.compile(r"nationstate|diplom|subsid|grant|boycott|consulate|embassy", re.IGNORECASE)),
]

NOISE_RE = re.compile(
    r"ui|resource|textstyle|picture|dialog|mfc|sharedstring|loadui|stringresource|"
    r"pathtail|filemetadata|install|environment|argv|envp|messagebyhwnd|copypath",
    re.IGNORECASE,
)

GAMEPLAY_RE = re.compile(
    r"hex|tile|neighbor|direction|movement|path|wrap|tactical|actionclass|cursormodeprofile|"
    r"civilian|workorder|improve|mine|farm|forester|prospect|army|navy|taskforce|war|battle|"
    r"turn|nationstate|diplom|industry|order",
    re.IGNORECASE,
)


def infer_domain(callee_blob: str) -> str:
    for domain, rx in DOMAIN_KEYWORDS:
        if rx.search(callee_blob):
            return domain
    return "Gameplay"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--min-hits", type=int, default=1)
    ap.add_argument("--min-unique-callees", type=int, default=1)
    ap.add_argument("--max-rows", type=int, default=0)
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))

    out = []
    for r in rows:
        caller_name = (r.get("caller_name") or "").strip()
        if not caller_name.startswith("FUN_"):
            continue

        hits = int((r.get("total_hits") or "0").strip() or 0)
        uniq = int((r.get("unique_callees") or "0").strip() or 0)
        if hits < args.min_hits or uniq < args.min_unique_callees:
            continue

        callee_blob = (r.get("callee_names") or "").strip()
        if not callee_blob:
            continue
        if NOISE_RE.search(callee_blob):
            # skip rows that are dominated by UI/infra helpers
            if not GAMEPLAY_RE.search(callee_blob):
                continue
            # still skip if gameplay signal is very weak
            if hits <= 1 and uniq <= 1:
                continue

        if not GAMEPLAY_RE.search(callee_blob):
            continue

        addr = (r.get("caller_addr") or "").strip()
        if not addr.startswith("0x"):
            continue
        hex_part = addr[2:].lower()
        domain = infer_domain(callee_blob)
        new_name = f"Cluster_{domain}Hint_{hex_part}"
        comment = f"[Hint] unresolved gameplay caller; observed callees: {callee_blob}"
        out.append({"address": addr, "new_name": new_name, "comment": comment})

    # Keep deterministic output and favor higher-call rows first.
    out.sort(key=lambda x: x["address"])

    if args.max_rows > 0:
        out = out[: args.max_rows]

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        wr.writeheader()
        wr.writerows(out)

    print(f"[saved] {out_csv} rows={len(out)}")
    for row in out[:80]:
        print(f"{row['address']},{row['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
