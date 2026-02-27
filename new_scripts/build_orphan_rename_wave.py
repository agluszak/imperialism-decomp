#!/usr/bin/env python3
"""
Build reusable orphan-rename wave CSVs from triage output.

Input CSV:
  output of new_scripts/triage_orphan_functions.py

Output CSV:
  address,new_name,comment

Modes:
  - leaf_nocall:     classification=orphan_leaf_unknown and call_count==0
  - callchain_small: classification=orphan_unknown_with_calls and call_count<=max-calls
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def i(text: str | None) -> int:
    try:
        return int((text or "").strip() or "0")
    except Exception:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="orphan triage csv")
    ap.add_argument("--out-csv", required=True, help="rename wave csv output")
    ap.add_argument(
        "--mode",
        required=True,
        choices=["leaf_nocall", "callchain_small"],
        help="rename wave mode",
    )
    ap.add_argument("--min-ins", type=int, default=0)
    ap.add_argument("--max-ins", type=int, default=12)
    ap.add_argument("--min-calls", type=int, default=0)
    ap.add_argument("--max-calls", type=int, default=2)
    args = ap.parse_args()

    in_csv = Path(args.in_csv).resolve()
    out_csv = Path(args.out_csv).resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    if not in_csv.exists():
        print(f"[error] missing input csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    out: list[dict[str, str]] = []

    for r in rows:
        name = (r.get("name") or "").strip()
        if not name.startswith("FUN_"):
            continue
        addr = (r.get("address") or "").strip().lower()
        if not addr.startswith("0x"):
            continue

        ins = i(r.get("instruction_count"))
        calls = i(r.get("call_count"))
        klass = (r.get("classification") or "").strip()

        if ins < args.min_ins or ins > args.max_ins:
            continue
        if calls < args.min_calls or calls > args.max_calls:
            continue

        if args.mode == "leaf_nocall":
            if klass != "orphan_leaf_unknown" or calls != 0:
                continue
            new_name = f"OrphanLeaf_NoCall_Ins{ins:02d}_{addr[2:]}"
            comment = f"[OrphanLeaf] no incoming code refs, no calls, instructions={ins}"
        else:
            if klass != "orphan_unknown_with_calls":
                continue
            new_name = f"OrphanCallChain_C{calls}_I{ins:02d}_{addr[2:]}"
            comment = (
                f"[OrphanCallChain] no incoming code refs; calls={calls}; instructions={ins}"
            )

        out.append({"address": addr, "new_name": new_name, "comment": comment})

    out.sort(key=lambda x: x["address"])
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(out)

    print(
        f"[saved] {out_csv} rows={len(out)} mode={args.mode} "
        f"ins={args.min_ins}..{args.max_ins} calls={args.min_calls}..{args.max_calls}"
    )
    for r in out[:120]:
        print(f"{r['address']},{r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
