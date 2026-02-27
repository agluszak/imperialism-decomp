#!/usr/bin/env python3
"""
Inventory PTR_GetCObjectRuntimeClass_* symbols and constructor-like initializer refs.

Outputs:
  - <out-prefix>_symbols.csv
  - <out-prefix>_refs.csv
  - <out-prefix>_summary.txt

Usage:
  uv run impk inventory_runtime_class_ptr_initializers \
    --out-prefix tmp_decomp/runtime_class_ptr_inventory
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
# Accept both legacy raw-address labels and semantically enriched pointer labels.
RX_PTR = re.compile(r"^PTR_GetCObjectRuntimeClass_")
RX_THIS_INIT = re.compile(r"\[\s*E(C|A)X\s*\]", re.IGNORECASE)

def parse_hex_addr(addr) -> int:
    return int(str(addr), 16) & 0xFFFFFFFF

def is_global_ns(ns, global_ns) -> bool:
    return ns is None or ns == global_ns or ns.getName() == "Global"

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/runtime_class_ptr_inventory",
        help="Output file prefix (without suffix)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_prefix = Path(args.out_prefix)
    if not out_prefix.is_absolute():
        out_prefix = root / out_prefix
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    out_symbols = out_prefix.with_name(out_prefix.name + "_symbols.csv")
    out_refs = out_prefix.with_name(out_prefix.name + "_refs.csv")
    out_summary = out_prefix.with_name(out_prefix.name + "_summary.txt")

    symbol_rows: list[dict[str, str]] = []
    ref_rows: list[dict[str, str]] = []

    with open_program(root) as program:
        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        listing = program.getListing()
        global_ns = program.getGlobalNamespace()

        ptr_syms = []
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            s = sit.next()
            if RX_PTR.match(s.getName()):
                ptr_syms.append(s)

        ptr_syms.sort(key=lambda s: parse_hex_addr(s.getAddress()))

        for s in ptr_syms:
            ptr_name = s.getName()
            ptr_addr = parse_hex_addr(s.getAddress())
            same_addr_syms = st.getSymbols(s.getAddress())
            colocated = []
            for cs in same_addr_syms:
                colocated.append(cs.getName())
            colocated = sorted(set(colocated))

            symbol_rows.append(
                {
                    "ptr_symbol": ptr_name,
                    "ptr_addr": f"0x{ptr_addr:08x}",
                    "colocated_symbols": ";".join(colocated),
                }
            )

            refs = rm.getReferencesTo(s.getAddress())
            while refs.hasNext():
                r = refs.next()
                from_addr = r.getFromAddress()
                from_int = parse_hex_addr(from_addr)
                fn = fm.getFunctionContaining(from_addr)
                ins = listing.getInstructionAt(from_addr)
                ins_text = "" if ins is None else str(ins)

                fn_addr = ""
                fn_name = "<no_func>"
                fn_ns = ""
                fn_cc = ""
                fn_is_global = "1"
                if fn is not None:
                    fn_entry = parse_hex_addr(fn.getEntryPoint())
                    fn_addr = f"0x{fn_entry:08x}"
                    fn_name = fn.getName()
                    ns = fn.getParentNamespace()
                    if not is_global_ns(ns, global_ns):
                        fn_ns = ns.getName()
                        fn_is_global = "0"
                    fn_cc = fn.getCallingConventionName() or ""

                init_like = "1" if RX_THIS_INIT.search(ins_text) else "0"
                ref_rows.append(
                    {
                        "ptr_symbol": ptr_name,
                        "ptr_addr": f"0x{ptr_addr:08x}",
                        "from_addr": f"0x{from_int:08x}",
                        "ref_type": str(r.getReferenceType()),
                        "function_addr": fn_addr,
                        "function_name": fn_name,
                        "function_namespace": fn_ns,
                        "function_calling_convention": fn_cc,
                        "function_is_global": fn_is_global,
                        "initializer_like": init_like,
                        "instruction": ins_text,
                    }
                )

    symbol_rows.sort(key=lambda r: int(r["ptr_addr"], 16))
    ref_rows.sort(
        key=lambda r: (
            int(r["ptr_addr"], 16),
            int(r["function_addr"], 16) if r["function_addr"] else 0,
            int(r["from_addr"], 16),
        )
    )

    with out_symbols.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["ptr_symbol", "ptr_addr", "colocated_symbols"])
        w.writeheader()
        w.writerows(symbol_rows)

    with out_refs.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "ptr_symbol",
                "ptr_addr",
                "from_addr",
                "ref_type",
                "function_addr",
                "function_name",
                "function_namespace",
                "function_calling_convention",
                "function_is_global",
                "initializer_like",
                "instruction",
            ],
        )
        w.writeheader()
        w.writerows(ref_rows)

    refs_with_func = [r for r in ref_rows if r["function_addr"]]
    init_like = [r for r in refs_with_func if r["initializer_like"] == "1"]
    global_init_like = [
        r
        for r in init_like
        if r["function_is_global"] == "1" and r["function_name"] not in ("<no_func>", "")
    ]

    summary_lines = [
        f"ptr_symbol_count={len(symbol_rows)}",
        f"total_refs={len(ref_rows)}",
        f"refs_with_function={len(refs_with_func)}",
        f"initializer_like_refs={len(init_like)}",
        f"initializer_like_global_refs={len(global_init_like)}",
    ]
    out_summary.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(f"[saved] {out_symbols} rows={len(symbol_rows)}")
    print(f"[saved] {out_refs} rows={len(ref_rows)}")
    print(f"[saved] {out_summary}")
    for line in summary_lines:
        print(line)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
