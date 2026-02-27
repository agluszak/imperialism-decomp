#!/usr/bin/env python3
"""
Generate CSV pairs for single-JMP thunk functions.

Output CSV columns:
  address,target_addr,name,target_name,namespace

Usage:
  uv run impk generate_single_jmp_thunk_pairs \
    --namespace TradeControl \
    --out-csv tmp_decomp/tradecontrol_single_jmp_pairs.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_int

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="", help="Optional exact namespace filter")
    ap.add_argument("--start", default="", help="Optional start address")
    ap.add_argument("--end", default="", help="Optional end address (exclusive)")
    ap.add_argument("--out-csv", required=True, help="Output CSV")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    ns_filter = args.namespace.strip()
    start = parse_int(args.start) if args.start else None
    end = parse_int(args.end) if args.end else None
    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []
    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()
        global_ns = program.getGlobalNamespace()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ep = int(str(fn.getEntryPoint()), 16)
            if start is not None and ep < start:
                continue
            if end is not None and ep >= end:
                continue

            ns = fn.getParentNamespace()
            ns_name = "Global" if ns is None or ns == global_ns else ns.getName()
            if ns_filter and ns_name != ns_filter:
                continue

            ins = list(listing.getInstructions(fn.getBody(), True))
            if len(ins) != 1:
                continue
            i0 = ins[0]
            text = str(i0)
            if not text.startswith("JMP "):
                continue

            tgt_fn = None
            refs = i0.getReferencesFrom()
            for ref in refs:
                tgt = ref.getToAddress()
                tf = fm.getFunctionAt(tgt)
                if tf is None:
                    continue
                tgt_ep = int(str(tf.getEntryPoint()), 16)
                if tgt_ep == int(str(tgt), 16):
                    tgt_fn = tf
                    break
            if tgt_fn is None:
                continue

            tgt_ep = int(str(tgt_fn.getEntryPoint()), 16)
            rows.append(
                {
                    "address": f"0x{ep:08x}",
                    "target_addr": f"0x{tgt_ep:08x}",
                    "name": fn.getName(),
                    "target_name": tgt_fn.getName(),
                    "namespace": ns_name,
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["address", "target_addr", "name", "target_name", "namespace"]
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:200]:
        print(
            f"{r['address']} {r['namespace']}::{r['name']} -> {r['target_addr']} {r['target_name']}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
