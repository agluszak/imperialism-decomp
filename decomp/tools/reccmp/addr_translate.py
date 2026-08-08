#!/usr/bin/env python3
"""Translate original-binary addresses to recomp addresses (and back) via reccmp.

winedbg breakpoints need *recomp* addresses/symbols, but every note, memory, Ghidra
query, and `// FUNCTION` marker speaks *original* addresses. reccmp already pairs
the two (by marker); this surfaces that pairing as a one-line lookup:

    just addr 0x491cc0            # orig -> recomp + name + match %
    just addr 0x448cd0            # recomp -> orig (direction auto-detected)

Runs one fresh, address-filtered reccmp comparison. Each query is checked in
both address spaces in the same process, with original-address matches taking
precedence when a numeric address exists in both images.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.common.reccmp_report import run_report
from tools.common.report_score import effective_matching

def load_entities(
    target: str, build_dir: Path, queries: list[int]
) -> list[dict]:
    return run_report(
        target,
        build_dir,
        diet=True,
        orig_addresses=queries,
        recomp_addresses=queries,
    )


def norm_hex(value: str | None) -> int | None:
    if not value or value == "various":
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True)
    ap.add_argument("--build-dir", required=True, type=Path)
    ap.add_argument("addrs", nargs="+", help="hex addresses, original or recomp")
    args = ap.parse_args()

    queries = [int(raw, 16) for raw in args.addrs]
    entities = load_entities(args.target, args.build_dir, queries)
    by_orig: dict[int, dict] = {}
    by_recomp: dict[int, dict] = {}

    def index(rows: list[dict]) -> None:
        for ent in rows:
            orig = norm_hex(ent.get("address"))
            recomp = norm_hex(ent.get("recomp"))
            if orig is not None:
                by_orig[orig] = ent
            if recomp is not None:
                by_recomp[recomp] = ent

    index(entities)
    missing = [q for q in queries if q not in by_orig and q not in by_recomp]
    if missing:
        # The address-filtered run only loads PDB object modules reccmp can
        # prove; functions in unprovable modules silently drop out. Fall back
        # to one unfiltered (full-corpus) report for the stragglers.
        index(run_report(args.target, args.build_dir, diet=True))
        rescued = [q for q in missing if q in by_orig or q in by_recomp]
        if rescued:
            # bd t401 regression tell: the filtered report dropped a pairable
            # address. Diagnose with `reccmp-reccmp --orig-address 0x... --json`
            # and compare the selected module ids against the TU's obj path in
            # the PDB module table (reccmp.cvdump.targeted.select_modules).
            print(
                "WARNING: address-filtered reccmp report dropped "
                + ", ".join(f"0x{q:08x}" for q in rescued)
                + "; the full-corpus fallback found them (bd t401 recurrence)",
                file=sys.stderr,
            )

    rc = 0
    for query in queries:
        ent = by_orig.get(query)
        direction = "orig->recomp"
        if ent is None:
            ent = by_recomp.get(query)
            direction = "recomp->orig"
        if ent is None:
            print(f"0x{query:08x}: no reccmp pairing (unowned address, or not a function entry)")
            rc = 1
            continue
        orig = norm_hex(ent.get("address"))
        recomp = norm_hex(ent.get("recomp"))
        name = ent.get("name", "?")
        score = ent.get("matching")
        score_pct = f"{score * 100:.2f}%" if isinstance(score, (int, float)) else "?"
        if ent["comparison"]["status"] == "effective":
            score_pct = f"{effective_matching(ent) * 100:.2f}% (effective, raw {score_pct})"
        orig_str = f"0x{orig:08x}" if orig is not None else "?"
        recomp_str = f"0x{recomp:08x}" if recomp is not None else "(not linked)"
        print(f"[{direction}] orig {orig_str}  recomp {recomp_str}  {score_pct}  {name}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
