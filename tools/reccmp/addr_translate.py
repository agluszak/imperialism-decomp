#!/usr/bin/env python3
"""Translate original-binary addresses to recomp addresses (and back) via reccmp.

winedbg breakpoints need *recomp* addresses/symbols, but every note, memory, Ghidra
query, and `// FUNCTION` marker speaks *original* addresses. reccmp already pairs
the two (by marker); this surfaces that pairing as a one-line lookup:

    just addr 0x491cc0            # orig -> recomp + name + match %
    just addr 0x448cd0            # recomp -> orig (direction auto-detected)

Runs `reccmp-reccmp --json` once (~4s over all ~9600 functions; same approach as
tools.reccmp.compare_batch) and caches the result next to the build until the
recomp binary/PDB changes, so repeat lookups are instant.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.common.reccmp_report import run_report
from tools.common.report_score import effective_matching

CACHE_NAME = "reccmp_addr_cache.json"


def _build_stamp(build_dir: Path) -> float:
    stamp = 0.0
    for pattern in ("*.exe", "*.pdb", "*.EXE", "*.PDB"):
        for path in build_dir.glob(pattern):
            stamp = max(stamp, path.stat().st_mtime)
    return stamp


def load_entities(target: str, build_dir: Path) -> list[dict]:
    cache_path = build_dir / CACHE_NAME
    stamp = _build_stamp(build_dir)
    if cache_path.is_file():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("stamp") == stamp:
                return cached["data"]
        except (json.JSONDecodeError, KeyError):
            pass
    data = run_report(target, build_dir)
    cache_path.write_text(json.dumps({"stamp": stamp, "data": data}), encoding="utf-8")
    return data


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

    entities = load_entities(args.target, args.build_dir)
    by_orig: dict[int, dict] = {}
    by_recomp: dict[int, dict] = {}
    for ent in entities:
        orig = norm_hex(ent.get("address"))
        recomp = norm_hex(ent.get("recomp"))
        if orig is not None:
            by_orig[orig] = ent
        if recomp is not None:
            by_recomp[recomp] = ent

    rc = 0
    for raw in args.addrs:
        query = int(raw, 16)
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
