#!/usr/bin/env python3
"""
Rank CSV address rows by reference count.

Input CSV:
- must include `address` column
- any extra columns are preserved

Output CSV:
- all input columns +:
  - xref_count
  - unique_callers
  - caller_names

Usage:
  .venv/bin/python new_scripts/rank_csv_addresses_by_xrefs.py <in_csv> <out_csv>
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("in_csv")
    ap.add_argument("out_csv")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    if not in_csv.exists():
        print(f"missing input csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("no input rows")
        return 0
    if "address" not in rows[0]:
        print("input csv missing 'address' column")
        return 1

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()

        out = []
        for row in rows:
            addr_txt = (row.get("address") or "").strip()
            if not addr_txt:
                continue
            try:
                addr_int = parse_hex(addr_txt)
            except Exception:
                row["xref_count"] = "0"
                row["unique_callers"] = "0"
                row["caller_names"] = ""
                out.append(row)
                continue

            addr = af.getAddress(f"0x{addr_int:08x}")
            refs = rm.getReferencesTo(addr)
            xref_count = 0
            caller_counts = defaultdict(int)
            for ref in refs:
                xref_count += 1
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                caller_counts[caller.getName()] += 1

            callers_sorted = sorted(caller_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            row["xref_count"] = str(xref_count)
            row["unique_callers"] = str(len(caller_counts))
            row["caller_names"] = ";".join(name for name, _ in callers_sorted[:12])
            out.append(row)

    out.sort(
        key=lambda r: (
            -int(r.get("xref_count") or 0),
            -int(r.get("unique_callers") or 0),
            r.get("address") or "",
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(out[0].keys())
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(out)

    print(f"[saved] {out_csv} rows={len(out)}")
    for r in out[:120]:
        print(
            f"{r.get('address')},{r.get('new_name','')},"
            f"xrefs={r.get('xref_count')},callers={r.get('unique_callers')},"
            f"{r.get('caller_names','')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
