#!/usr/bin/env python3
"""
Classify no-func branch-source rows into actionable categories.

Input:
  detail CSV from inventory_no_func_branch_sources.py

Output:
  - <out-prefix>_classified.csv
  - <out-prefix>_summary.txt

Categories:
  - owner_empty_missing_boundary:
      inferred_start_owner is empty (candidate for function recovery).
  - owner_hole_within_span:
      source is not in any function but lies within min..max address span of
      inferred owner function body (likely intentional decode island/hole).
  - owner_tail_island_near_span:
      source lies just past owner coarse span end by a small tolerance.
  - owner_outside_span_review:
      source does not lie in owner's body span (needs manual review).
  - parse_error:
      malformed/unknown row.

Usage:
  uv run impk classify_no_func_branch_islands \
    --detail-csv tmp_decomp/batch777_no_func_branch_sources_postfun19_detail.csv \
    --out-prefix tmp_decomp/batch777_no_func_branch_sources_postfun19
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

def parse_hex_addr(text: str) -> int:
    t = (text or "").strip()
    if not t:
        raise ValueError("empty address")
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)

def body_span(fn) -> tuple[int, int]:
    """
    Compute coarse min..max span for function body address ranges.
    """
    mn = None
    mx = None
    ar = fn.getBody().getAddressRanges()
    while ar.hasNext():
        r = ar.next()
        lo = int(str(r.getMinAddress()), 16) & 0xFFFFFFFF
        hi = int(str(r.getMaxAddress()), 16) & 0xFFFFFFFF
        if mn is None or lo < mn:
            mn = lo
        if mx is None or hi > mx:
            mx = hi
    if mn is None or mx is None:
        ep = int(str(fn.getEntryPoint()), 16) & 0xFFFFFFFF
        return ep, ep
    return mn, mx

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--detail-csv", required=True, help="Detail CSV from no-func inventory")
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/no_func_branch_sources",
        help="Output prefix (without suffix)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--span-near-bytes",
        type=int,
        default=0x20,
        help="Classify source as near-span tail island when within this many bytes past owner span",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    detail_csv = Path(args.detail_csv)
    if not detail_csv.is_absolute():
        detail_csv = root / detail_csv
    if not detail_csv.exists():
        print(f"[error] missing detail csv: {detail_csv}")
        return 1

    out_prefix = Path(args.out_prefix)
    if not out_prefix.is_absolute():
        out_prefix = root / out_prefix
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    out_csv = out_prefix.with_name(out_prefix.name + "_classified.csv")
    out_txt = out_prefix.with_name(out_prefix.name + "_classified_summary.txt")

    rows = list(csv.DictReader(detail_csv.open("r", encoding="utf-8", newline="")))
    if not rows:
        out_csv.write_text(
            "source_addr,classification,reason,source_owner,owner_entry,owner_span_min,owner_span_max,inferred_start,inferred_start_owner\n",
            encoding="utf-8",
        )
        out_txt.write_text("rows=0\n", encoding="utf-8")
        print(f"[saved] {out_csv} rows=0")
        print(f"[saved] {out_txt}")
        return 0

    out_rows: list[dict[str, str]] = []
    ctr = Counter()

    with open_program(root) as program:
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        for r in rows:
            src_txt = (r.get("source_addr") or "").strip()
            inf_owner = (r.get("inferred_start_owner") or "").strip()
            inf_start = (r.get("inferred_start") or "").strip()

            base = {
                "source_addr": src_txt,
                "inferred_start": inf_start,
                "inferred_start_owner": inf_owner,
                "source_owner": "",
                "owner_entry": "",
                "owner_span_min": "",
                "owner_span_max": "",
                "classification": "",
                "reason": "",
            }

            try:
                src_i = parse_hex_addr(src_txt)
                src_addr = af.getAddress(f"0x{src_i:08x}")
            except Exception:
                base["classification"] = "parse_error"
                base["reason"] = "invalid source_addr"
                out_rows.append(base)
                ctr[base["classification"]] += 1
                continue

            src_owner = fm.getFunctionContaining(src_addr)
            if src_owner is not None:
                base["source_owner"] = src_owner.getName()

            if not inf_owner:
                base["classification"] = "owner_empty_missing_boundary"
                base["reason"] = "inferred_start_owner is empty"
                out_rows.append(base)
                ctr[base["classification"]] += 1
                continue

            owner_fn = None
            if inf_start:
                try:
                    inf_i = parse_hex_addr(inf_start)
                    inf_addr = af.getAddress(f"0x{inf_i:08x}")
                    owner_fn = fm.getFunctionContaining(inf_addr)
                except Exception:
                    owner_fn = None

            if owner_fn is None:
                base["classification"] = "owner_outside_span_review"
                base["reason"] = "owner function not found from inferred_start"
                out_rows.append(base)
                ctr[base["classification"]] += 1
                continue

            o_entry = int(str(owner_fn.getEntryPoint()), 16) & 0xFFFFFFFF
            span_lo, span_hi = body_span(owner_fn)
            base["owner_entry"] = f"0x{o_entry:08x}"
            base["owner_span_min"] = f"0x{span_lo:08x}"
            base["owner_span_max"] = f"0x{span_hi:08x}"

            if span_lo <= src_i <= span_hi:
                base["classification"] = "owner_hole_within_span"
                base["reason"] = "source lies inside owner coarse span but outside function body"
            elif span_hi < src_i <= span_hi + args.span_near_bytes:
                base["classification"] = "owner_tail_island_near_span"
                base["reason"] = (
                    f"source is near owner coarse span end (delta=0x{src_i - span_hi:x})"
                )
            else:
                base["classification"] = "owner_outside_span_review"
                base["reason"] = "source outside owner coarse span"

            out_rows.append(base)
            ctr[base["classification"]] += 1

    out_rows.sort(key=lambda x: int(x["source_addr"], 16) if x["source_addr"] else 0)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "source_addr",
                "classification",
                "reason",
                "source_owner",
                "owner_entry",
                "owner_span_min",
                "owner_span_max",
                "inferred_start",
                "inferred_start_owner",
            ],
        )
        w.writeheader()
        w.writerows(out_rows)

    lines = [
        f"rows={len(out_rows)}",
        *(f"{k}={v}" for k, v in sorted(ctr.items())),
    ]
    out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[saved] {out_csv} rows={len(out_rows)}")
    print(f"[saved] {out_txt}")
    for line in lines:
        print(line)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
