#!/usr/bin/env python3
"""One-stop status for a function address (no Ghidra / no build — instant).

Joins the four scattered sources you otherwise grep by hand every time you look at a
function: config/original_entities.csv (curated name/size/prototype), source markers
(marker-derived ownership), the Ghidra evidence export index (the reference body's
location + export status), and the reccmp baseline report (current match %).

usage:
  func_status 0xADDR [0xADDR ...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tools.common.baseline_staleness import warn_if_baseline_stale
from tools.common.pipe_csv import read_pipe_rows
from tools.common.report_score import effective_matching

REPO_ROOT = Path(__file__).resolve().parents[2]
SYMBOLS_CSV = REPO_ROOT / "config" / "original_entities.csv"
AUTOGEN_INDEX = (REPO_ROOT / "build-msvc500" / "evidence" / "ghidra-export"
                 / "src" / "index.csv")
BASELINE_REPORT = REPO_ROOT / "config" / "baselines" / "reccmp_progress_baseline.report.json"


def _index_by_address(path: Path) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if not path.is_file():
        return out
    for row in read_pipe_rows(path):
        addr = (row.get("address") or "").strip().lower().removeprefix("0x")
        if addr:
            out[addr.lstrip("0") or "0"] = row
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
            out[addr.lower().replace("0x", "").lstrip("0") or "0"] = effective_matching(entry)
    return out


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: func_status 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

    warn_if_baseline_stale(REPO_ROOT)

    from tools.source_model import ownership_kind, ownership_view

    symbols = _index_by_address(SYMBOLS_CSV)
    ownership = {
        f"{a:x}": {"ownership": ownership_kind(c.kind, c.origin),
                   "target_cpp": c.file,
                   "note": f"marker {c.kind} at {c.file}:{c.line}"}
        for a, c in ownership_view(REPO_ROOT).items()
    }
    autogen = _index_by_address(AUTOGEN_INDEX)
    scores = _scores()

    for raw in argv:
        addr_int = int(raw, 16)
        key = _norm(addr_int)
        print(f"=== 0x{addr_int:08x} ===")

        sym = symbols.get(key)
        if sym:
            print(
                f"  symbols.csv : name={sym.get('name', '')!r} "
                f"size={sym.get('size', '')} type={sym.get('type', '')}"
            )
            if sym.get("prototype"):
                print(f"                proto={sym['prototype']}")
        else:
            print("  symbols.csv : (not found)")

        own = ownership.get(key)
        if own:
            note = f" note={own['note']}" if own.get("note") else ""
            print(f"  ownership   : {own.get('ownership', '')} -> {own.get('target_cpp', '')}{note}")
        else:
            print("  ownership   : (stub / unowned — generated into build-msvc500/generated/stubs)")

        ag = autogen.get(key)
        if ag:
            print(f"  autogen body: {ag.get('file', '')} (status={ag.get('status', '')})")

        if key in scores:
            print(f"  reccmp score: {scores[key] * 100:.2f}%  (baseline report)")
        else:
            print("  reccmp score: (not in baseline report)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
