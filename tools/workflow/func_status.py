#!/usr/bin/env python3
"""One-stop status for a function address (no Ghidra / no build — instant).

Joins the four scattered sources you otherwise grep by hand every time you look at a
function: config/symbols.csv (curated name/size/prototype), config/function_ownership.csv
(who owns it and how it was paired), src/ghidra_autogen/index.csv (the reference body's
location + export status), and the reccmp baseline report (current match %).

usage:
  func_status 0xADDR [0xADDR ...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SYMBOLS_CSV = REPO_ROOT / "config" / "symbols.csv"
OWNERSHIP_CSV = REPO_ROOT / "config" / "function_ownership.csv"
AUTOGEN_INDEX = REPO_ROOT / "src" / "ghidra_autogen" / "index.csv"
BASELINE_REPORT = REPO_ROOT / "config" / "reccmp_progress_baseline.report.json"


def _index_csv(path: Path, ncols: int) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split("|")
        if len(parts) < ncols:
            continue
        out[parts[0].lower().lstrip("0") or "0"] = parts
    return out


def _norm(addr_int: int) -> str:
    return f"{addr_int:x}".lstrip("0") or "0"


def _scores() -> dict[str, float]:
    out: dict[str, float] = {}
    if not BASELINE_REPORT.is_file():
        return out
    for entry in json.loads(BASELINE_REPORT.read_text(encoding="utf-8")).get("data", []):
        addr = entry.get("address")
        if addr:
            out[addr.lower().replace("0x", "").lstrip("0") or "0"] = float(entry.get("matching", 0.0))
    return out


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: func_status 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

    symbols = _index_csv(SYMBOLS_CSV, 6)
    ownership = _index_csv(OWNERSHIP_CSV, 3)
    autogen = _index_csv(AUTOGEN_INDEX, 5)
    scores = _scores()

    for raw in argv:
        addr_int = int(raw, 16)
        key = _norm(addr_int)
        print(f"=== 0x{addr_int:08x} ===")

        sym = symbols.get(key)
        if sym:
            print(f"  symbols.csv : name={sym[1]!r} size={sym[3]} type={sym[4]}")
            if len(sym) > 5 and sym[5]:
                print(f"                proto={sym[5]}")
        else:
            print("  symbols.csv : (not found)")

        own = ownership.get(key)
        if own:
            note = f" note={own[3]}" if len(own) > 3 and own[3] else ""
            print(f"  ownership   : {own[2]} -> {own[1]}{note}")
        else:
            print("  ownership   : (stub / unowned — lives in src/autogen/stubs)")

        ag = autogen.get(key)
        if ag:
            print(f"  autogen body: {ag[3]} (status={ag[4]})")

        if key in scores:
            print(f"  reccmp score: {scores[key] * 100:.2f}%  (baseline report)")
        else:
            print("  reccmp score: (not in baseline report)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
