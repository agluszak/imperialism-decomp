#!/usr/bin/env python3
"""
Find functions whose signature string matches a regex.

Usage:
  .venv/bin/python new_scripts/list_functions_by_signature_regex.py \
    --pattern "TradeControl \\* this" \
    --out-csv tmp_decomp/tradecontrol_sig_matches.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


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
    ap.add_argument("--pattern", required=True, help="Regex applied to full signature text")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--name-pattern", default="", help="Optional regex for function name")
    ap.add_argument("--namespace", default="", help="Optional namespace exact match")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    sig_rx = re.compile(args.pattern)
    name_rx = re.compile(args.name_pattern) if args.name_pattern else None
    ns_filter = args.namespace.strip()
    out_csv = Path(args.out_csv)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            sig = str(f.getSignature())
            if not sig_rx.search(sig):
                continue
            name = f.getName()
            if name_rx and not name_rx.search(name):
                continue
            ns = f.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()
            if ns_filter and ns_name != ns_filter:
                continue
            ep = int(str(f.getEntryPoint()), 16)
            rows.append(
                {
                    "address": f"0x{ep:08x}",
                    "namespace": ns_name,
                    "name": name,
                    "calling_convention": f.getCallingConventionName() or "",
                    "signature": sig,
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["address", "namespace", "name", "calling_convention", "signature"],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(f"{r['address']} {r['namespace']}::{r['name']} cc={r['calling_convention']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
