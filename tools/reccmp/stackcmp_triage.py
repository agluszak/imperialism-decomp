#!/usr/bin/env python3
"""Batch stack-layout triage: run reccmp-stackcmp over near-match functions.

`just stackcmp` inspects one function; nothing surfaced which of the hundreds
of near-matching functions fail *because of stack layout*. This picks
candidates from the reccmp report (score in [--min, --max), largest first),
runs reccmp-stackcmp on each, and summarizes per function:

  multi   stack variables matching multiple counterparts (✗) — real layout bug
  order   1:1 variables in the wrong order (⇄) — declaration-order fix
  struct  structural-mismatch blocks reported before the table
  verdict stackcmp's own final judgement (BAD = not a 1:1 correspondence)

Each stackcmp run re-parses the PDB (~10-30s), so batch size is capped by
--limit (default 12). Explicit addresses skip the report-based selection.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

from tools.common.reccmp_report import run_report
from tools.common.repo import repo_root_from_file
from tools.common.report_score import effective_matching

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def analyze_output(text: str) -> dict[str, int | str]:
    plain = ANSI_RE.sub("", text)
    return {
        "multi": plain.count("✗"),
        "order": plain.count("⇄"),
        "struct": plain.count("Structural mismatch at"),
        "verdict": "BAD" if "not in a 1:1 correspondence" in plain else "ok",
    }


def run_stackcmp(target: str, build_dir: Path, addr: int, timeout: int) -> str:
    proc = subprocess.run(
        ["uv", "run", "reccmp-stackcmp", "--target", target, f"0x{addr:x}"],
        cwd=build_dir,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.stdout + proc.stderr


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="IMPERIALISM")
    ap.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    ap.add_argument("--min", type=float, default=0.40, help="Lowest score considered")
    ap.add_argument("--max", type=float, default=0.999, help="Highest score considered")
    ap.add_argument("--limit", type=int, default=12, help="Max functions to run")
    ap.add_argument("--timeout", type=int, default=180, help="Per-run timeout (s)")
    ap.add_argument("addrs", nargs="*", help="Explicit addresses (skip selection)")
    args = ap.parse_args()

    build_dir = Path(args.build_dir)
    if args.addrs:
        chosen = [(int(a, 16), "?", 0.0) for a in args.addrs]
    else:
        rows = run_report(args.target, build_dir, diet=True)
        scored = [
            (int(r["address"], 16), r["name"], effective_matching(r))
            for r in rows
            if args.min <= effective_matching(r) < args.max
        ]
        scored.sort(key=lambda t: -t[2])
        chosen = scored[: args.limit]
        print(f"{len(scored)} functions in score range; running stackcmp on top {len(chosen)}")

    print("address|score|multi|order|struct|verdict|name")
    worst: list[tuple[int, str]] = []
    for addr, name, score in chosen:
        try:
            out = run_stackcmp(args.target, build_dir, addr, args.timeout)
        except subprocess.TimeoutExpired:
            print(f"0x{addr:08x}|{score * 100:.1f}|-|-|-|timeout|{name}")
            continue
        facts = analyze_output(out)
        print(
            f"0x{addr:08x}|{score * 100:.1f}|{facts['multi']}|{facts['order']}|"
            f"{facts['struct']}|{facts['verdict']}|{name}"
        )
        if facts["verdict"] == "BAD" or facts["multi"]:
            worst.append((addr, name))
    if worst:
        print("\nstack-layout suspects (fix locals/EH declaration order first):")
        for addr, name in worst:
            print(f"  just stackcmp 0x{addr:x}   # {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
