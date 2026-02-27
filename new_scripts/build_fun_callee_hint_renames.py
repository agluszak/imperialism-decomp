#!/usr/bin/env python3
"""
Build safe hint-style function rename CSV from FUN_* callee-candidate CSV.

Input format (from generate_fun_callee_candidates.py):
  callee_addr,callee_name,total_calls,unique_callers,caller_names

Output format (for apply_function_renames_csv.py):
  address,new_name,comment

Usage:
  .venv/bin/python new_scripts/build_fun_callee_hint_renames.py \
    --in-csv tmp_decomp/batch98_fun_callees_logic.csv \
    --out-csv tmp_decomp/batch99_fun_callee_hints.csv \
    --min-calls 2 --min-unique-callers 2
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


DOMAIN_KEYWORDS = [
    ("Tactical", re.compile(r"tactical|battle|combat|army|navy|unit", re.IGNORECASE)),
    ("MapTile", re.compile(r"map|tile|hex|neighbor|terrain|path|order", re.IGNORECASE)),
    ("Civilian", re.compile(r"civilian|workorder|improve|mine|farm|forester|prospect", re.IGNORECASE)),
    ("Trade", re.compile(r"trade|commodity|bid|offer|warehouse|transport", re.IGNORECASE)),
    ("NationState", re.compile(r"nationstate|nation|diplom|grant|subsid|boycott|consulate|embassy", re.IGNORECASE)),
    ("TurnState", re.compile(r"turnstate|turnevent|turn|dispatch", re.IGNORECASE)),
]

NOISE_RE = re.compile(
    r"ui|resource|textstyle|picture|dialog|window|view|toolbar|mfc|sharedstring|"
    r"loadui|stringresource|pathtail|filemetadata|install|environment|argv|envp|messagebyhwnd|copypath",
    re.IGNORECASE,
)

GAMEPLAY_RE = re.compile(
    r"map|tile|hex|terrain|path|order|tactical|battle|combat|army|navy|unit|civilian|"
    r"workorder|improve|mine|farm|forester|prospect|trade|commodity|bid|offer|transport|"
    r"nation|diplom|grant|subsid|boycott|consulate|embassy|turn|event|dispatch|mission|province",
    re.IGNORECASE,
)


def infer_domain(blob: str) -> str:
    for domain, rx in DOMAIN_KEYWORDS:
        if rx.search(blob):
            return domain
    return "Gameplay"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--min-calls", type=int, default=2)
    ap.add_argument("--min-unique-callers", type=int, default=2)
    ap.add_argument("--max-rows", type=int, default=0)
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))

    out = []
    for r in rows:
        callee_name = (r.get("callee_name") or "").strip()
        if not callee_name.startswith("FUN_"):
            continue

        calls = int((r.get("total_calls") or "0").strip() or 0)
        uniq = int((r.get("unique_callers") or "0").strip() or 0)
        if calls < args.min_calls or uniq < args.min_unique_callers:
            continue

        caller_blob = (r.get("caller_names") or "").strip()
        if not caller_blob:
            continue

        if NOISE_RE.search(caller_blob):
            if not GAMEPLAY_RE.search(caller_blob):
                continue
            if calls <= 2 and uniq <= 2:
                continue

        if not GAMEPLAY_RE.search(caller_blob):
            continue

        addr = (r.get("callee_addr") or "").strip()
        if not addr.startswith("0x"):
            continue

        hex_part = addr[2:].lower()
        domain = infer_domain(caller_blob)
        new_name = f"Cluster_{domain}CalleeHint_{hex_part}"
        comment = f"[Hint] unresolved gameplay callee; observed callers: {caller_blob}"
        out.append({"address": addr, "new_name": new_name, "comment": comment})

    out.sort(key=lambda x: x["address"])
    if args.max_rows > 0:
        out = out[: args.max_rows]

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        wr.writeheader()
        wr.writerows(out)

    print(f"[saved] {out_csv} rows={len(out)}")
    for row in out[:120]:
        print(f"{row['address']},{row['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
