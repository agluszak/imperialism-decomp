#!/usr/bin/env python3
"""Rank porting candidates: the biggest functions that are not yet well matched.

Pure config-file reader (no Ghidra / no build) — instant. Answers "what big, low-scoring
functions should I port next?" by joining config/symbols.csv (size), the reccmp baseline
report (per-function match %), and config/function_ownership.csv (owned vs stub).

usage:
  port_candidates [--range LO HI] [--min-size N] [--max-score PCT] [--limit N]
                  [--unowned-only] [--owned-only]

defaults: --min-size 100  --max-score 60  --limit 30

examples:
  port_candidates --range 0x52c000 0x530000       # unported map-subsystem functions
  port_candidates --min-size 500 --max-score 40   # the big, weakly-matched functions
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows

REPO_ROOT = Path(__file__).resolve().parents[2]
SYMBOLS_CSV = REPO_ROOT / "config" / "symbols.csv"
OWNERSHIP_CSV = REPO_ROOT / "config" / "function_ownership.csv"
BASELINE_REPORT = REPO_ROOT / "config" / "reccmp_progress_baseline.report.json"


def _parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 0)


def _load_symbols() -> dict[int, tuple[str, int, str]]:
    out: dict[int, tuple[str, int, str]] = {}
    for row in read_pipe_rows(SYMBOLS_CSV):
        kind = (row.get("type") or "").strip()
        if kind != "function":
            continue
        size = (row.get("size") or "").strip()
        try:
            out[int(row.get("address") or "", 16)] = (
                (row.get("name") or "").strip(),
                int(size) if size else 0,
                kind,
            )
        except ValueError:
            continue
    return out


def _load_ownership() -> dict[int, tuple[str, str]]:
    out: dict[int, tuple[str, str]] = {}
    if not OWNERSHIP_CSV.is_file():
        return out
    for row in read_pipe_rows(OWNERSHIP_CSV):
        try:
            out[int(row.get("address") or "", 16)] = (
                (row.get("target_cpp") or "").strip(),
                (row.get("ownership") or "").strip(),
            )
        except ValueError:
            continue
    return out


def _load_scores() -> dict[int, float]:
    out: dict[int, float] = {}
    if not BASELINE_REPORT.is_file():
        return out
    data = json.loads(BASELINE_REPORT.read_text(encoding="utf-8")).get("data", [])
    for entry in data:
        addr = entry.get("address")
        if not addr:
            continue
        try:
            out[int(addr, 16)] = float(entry.get("matching", 0.0))
        except (ValueError, TypeError):
            continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Rank porting candidates by size and match gap.")
    ap.add_argument("--range", nargs=2, metavar=("LO", "HI"))
    ap.add_argument("--min-size", type=int, default=100)
    ap.add_argument("--max-score", type=float, default=60.0)
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--unowned-only", action="store_true", help="only functions with no manual owner")
    ap.add_argument("--owned-only", action="store_true", help="only functions already owned manually")
    args = ap.parse_args()

    lo, hi = (0, 1 << 32)
    if args.range:
        lo, hi = _parse_int(args.range[0]), _parse_int(args.range[1])

    symbols = _load_symbols()
    ownership = _load_ownership()
    scores = _load_scores()

    rows = []
    for addr, (name, size, _kind) in symbols.items():
        if not (lo <= addr < hi) or size < args.min_size:
            continue
        if name.startswith("thunk_"):
            continue
        score = scores.get(addr, 0.0) * 100.0
        if score > args.max_score:
            continue
        owner_file, owner_kind = ownership.get(addr, ("", "(stub)"))
        is_manual = owner_kind == "manual"
        if args.unowned_only and is_manual:
            continue
        if args.owned_only and not is_manual:
            continue
        rows.append((size, score, addr, owner_kind, owner_file, name))

    rows.sort(key=lambda r: (-r[0], r[1]))
    rows = rows[: args.limit]

    print(f"{'address':<10} {'size':>6} {'score':>6}  {'owner':<8} name")
    print("-" * 88)
    for size, score, addr, owner_kind, owner_file, name in rows:
        owner = "manual" if owner_kind == "manual" else "stub"
        loc = f" [{owner_file}]" if owner_file else ""
        print(f"0x{addr:08x} {size:>6} {score:>5.1f}%  {owner:<8} {name}{loc}")
    if not rows:
        print("(no candidates match the filters)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
