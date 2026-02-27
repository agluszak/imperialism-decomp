#!/usr/bin/env python3
"""
List functions in an address range with namespace/signature metadata.

Usage:
  uv run impk list_functions_in_range \
    --start 0x00583b00 --end 0x0058c200 \
    --out-csv tmp_decomp/trade_range_functions.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_int

RX_MANGLED = re.compile(r"^\?")

def is_generic(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="range start (hex or dec)")
    ap.add_argument("--end", required=True, help="range end (hex or dec), exclusive")
    ap.add_argument("--namespace", default="", help="Filter to namespace name")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_int(args.start)
    end = parse_int(args.end)
    ns_filter = args.namespace.strip()
    out_csv = Path(args.out_csv)
    root = resolve_project_root(args.project_root)

    rows: list[dict[str, str]] = []
    with open_program(root) as program:
        fm = program.getFunctionManager()
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ep = int(str(f.getEntryPoint()), 16)
            if ep < start or ep >= end:
                continue

            ns = f.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()
            if ns_filter and ns_name != ns_filter:
                continue

            name = f.getName()
            sig = str(f.getSignature())
            cc = f.getCallingConventionName() or ""
            rows.append(
                {
                    "address": f"0x{ep:08x}",
                    "namespace": ns_name,
                    "name": name,
                    "calling_convention": cc,
                    "is_thiscall": "1" if cc == "__thiscall" else "0",
                    "is_mangled": "1" if RX_MANGLED.match(name) else "0",
                    "is_generic": "1" if is_generic(name) else "0",
                    "signature": sig,
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "namespace",
                "name",
                "calling_convention",
                "is_thiscall",
                "is_mangled",
                "is_generic",
                "signature",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    global_rows = [r for r in rows if r["namespace"] in ("Global", "")]
    global_thiscall = [r for r in global_rows if r["is_thiscall"] == "1"]
    global_mangled = [r for r in global_rows if r["is_mangled"] == "1"]
    print(f"[saved] {out_csv} rows={len(rows)}")
    print(f"global_total {len(global_rows)}")
    print(f"global_thiscall {len(global_thiscall)}")
    print(f"global_mangled {len(global_mangled)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
