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
    if any(query not in by_orig and query not in by_recomp for query in queries):
        # The address-filtered run only loads PDB object modules reccmp can
        # prove; functions in unprovable modules silently drop out. Fall back
        # to one unfiltered (full-corpus) report for the stragglers.
        index(run_report(args.target, args.build_dir, diet=True))

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
