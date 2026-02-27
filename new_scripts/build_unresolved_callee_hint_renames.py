#!/usr/bin/env python3
"""
Build conservative hint renames from unresolved snapshot rows with named callees.

Input:
  CSV from list_unresolved_functions_in_range.py, e.g.
  tmp_decomp/batch437_unresolved_0040_006f_snapshot_postNN.csv

Output:
  address,new_name,comment

Rename policy:
  - only functions named FUN_*
  - require minimum named_callee_count (default: 2)
  - optional instruction-count floor to skip tiny tails/stubs
  - domain inferred from named_callees string (keyword map)
  - non-semantic hint names to keep risk low:
      Cluster_<Domain>Hint_<addr_hex>
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


DOMAIN_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "Tactical",
        re.compile(r"tactical|battle|army|navy|unit|rally|target|deploy", re.IGNORECASE),
    ),
    (
        "Trade",
        re.compile(r"trade|commodity|bid|offer|transport|warehouse|deal", re.IGNORECASE),
    ),
    (
        "NationState",
        re.compile(
            r"nation|diplom|relation|treaty|embassy|consulate|grant|subsid|boycott",
            re.IGNORECASE,
        ),
    ),
    (
        "TurnState",
        re.compile(r"turnstate|turnevent|turn|dispatchturn", re.IGNORECASE),
    ),
    (
        "MapTile",
        re.compile(
            r"map|tile|hex|region|quickdraw|palette|blit|render|clip|stroke|fill",
            re.IGNORECASE,
        ),
    ),
    (
        "CityState",
        re.compile(r"city|production|minister|industry|building|recruit", re.IGNORECASE),
    ),
]


def infer_domain(named_callees: str) -> str:
    for domain, rx in DOMAIN_RULES:
        if rx.search(named_callees):
            return domain
    return "Gameplay"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="Unresolved snapshot CSV")
    ap.add_argument("--out-csv", required=True, help="Rename CSV output path")
    ap.add_argument(
        "--min-named-callees",
        type=int,
        default=2,
        help="Minimum named_callee_count",
    )
    ap.add_argument(
        "--min-instruction-count",
        type=int,
        default=20,
        help="Minimum instruction_count",
    )
    ap.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="Optional cap after sorting (0 = unlimited)",
    )
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))

    out: list[dict[str, str]] = []
    for r in rows:
        name = (r.get("name") or "").strip()
        if not name.startswith("FUN_"):
            continue
        try:
            named_callee_count = int((r.get("named_callee_count") or "0").strip() or 0)
            instruction_count = int((r.get("instruction_count") or "0").strip() or 0)
        except Exception:
            continue
        if named_callee_count < args.min_named_callees:
            continue
        if instruction_count < args.min_instruction_count:
            continue

        addr = (r.get("address") or "").strip()
        if not addr.startswith("0x"):
            continue
        hex_part = addr[2:].lower()
        named_callees = (r.get("named_callees") or "").strip()
        if not named_callees:
            continue

        domain = infer_domain(named_callees)
        out.append(
            {
                "address": addr,
                "new_name": f"Cluster_{domain}Hint_{hex_part}",
                "comment": (
                    "[CalleeHint] unresolved body with named callees; "
                    f"named_callee_count={named_callee_count}; callees={named_callees}"
                ),
                "_score_named": str(named_callee_count),
                "_score_instr": str(instruction_count),
            }
        )

    # Prefer high-signal rows first, deterministic by address after score.
    out.sort(
        key=lambda r: (
            -int(r["_score_named"]),
            -int(r["_score_instr"]),
            r["address"],
        )
    )
    if args.max_rows > 0:
        out = out[: args.max_rows]

    # Drop internal scoring columns for final CSV.
    final_rows = [
        {"address": r["address"], "new_name": r["new_name"], "comment": r["comment"]}
        for r in out
    ]

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(final_rows)

    print(
        f"[saved] {out_csv} rows={len(final_rows)} "
        f"min_named_callees={args.min_named_callees} min_instruction_count={args.min_instruction_count}"
    )
    for r in final_rows[:160]:
        print(f"{r['address']},{r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
