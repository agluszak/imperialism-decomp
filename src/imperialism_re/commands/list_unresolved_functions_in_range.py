#!/usr/bin/env python3
"""
List unresolved/generic functions in an address range with caller/callee pressure.

Usage:
  uv run impk list_unresolved_functions_in_range \
    --addr-min 0x00600000 --addr-max 0x0062ffff \
    --out-csv tmp_decomp/batchNN_unresolved_0060_0062.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def is_generic(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr-min", required=True, help="Min address, hex")
    ap.add_argument("--addr-max", required=True, help="Max address, hex (inclusive)")
    ap.add_argument(
        "--name-regex",
        default=r"^(FUN_|thunk_FUN_|Cluster_)",
        help="Filter unresolved names",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/unresolved_range.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    name_re = re.compile(args.name_regex)
    out_csv = Path(args.out_csv)
    root = resolve_project_root(args.project_root)

    rows: list[dict[str, str]] = []
    with open_program(root) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr < lo or addr > hi:
                continue
            name = f.getName()
            if not name_re.search(name):
                continue

            # callers
            refs_to = rm.getReferencesTo(af.getAddress(f"0x{addr:08x}"))
            callers_named = 0
            callers_generic = 0
            callers_total = 0
            callers_set = set()
            for ref in refs_to:
                c = fm.getFunctionContaining(ref.getFromAddress())
                if c is None:
                    continue
                caddr = c.getEntryPoint().getOffset() & 0xFFFFFFFF
                key = (caddr, c.getName())
                if key in callers_set:
                    continue
                callers_set.add(key)
                callers_total += 1
                if is_generic(c.getName()):
                    callers_generic += 1
                else:
                    callers_named += 1

            # callees and local shape
            instr_count = 0
            call_insn_count = 0
            callee_named = set()
            callee_generic = set()
            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                instr_count += 1
                if str(ins.getMnemonicString()).upper() != "CALL":
                    continue
                call_insn_count += 1
                refs = ins.getReferencesFrom()
                for ref in refs:
                    c = fm.getFunctionAt(ref.getToAddress())
                    if c is None:
                        continue
                    caddr_txt = str(c.getEntryPoint())
                    if caddr_txt.startswith("EXTERNAL:"):
                        continue
                    ctag = f"{c.getName()}@{caddr_txt}"
                    if is_generic(c.getName()):
                        callee_generic.add(ctag)
                    else:
                        callee_named.add(ctag)

            ns = f.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()

            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "name": name,
                    "namespace": ns_name,
                    "instruction_count": str(instr_count),
                    "call_insn_count": str(call_insn_count),
                    "xrefs_to_count": str(callers_total),
                    "named_caller_count": str(callers_named),
                    "generic_caller_count": str(callers_generic),
                    "named_callee_count": str(len(callee_named)),
                    "generic_callee_count": str(len(callee_generic)),
                    "named_callees": ";".join(sorted(callee_named)),
                    "sample_callers": ";".join(
                        sorted(f"{nm}@0x{ca:08x}" for ca, nm in callers_set)[:12]
                    ),
                }
            )

    rows.sort(
        key=lambda r: (
            -int(r["named_caller_count"]),
            -int(r["xrefs_to_count"]),
            -int(r["named_callee_count"]),
            r["address"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "name",
                "namespace",
                "instruction_count",
                "call_insn_count",
                "xrefs_to_count",
                "named_caller_count",
                "generic_caller_count",
                "named_callee_count",
                "generic_callee_count",
                "named_callees",
                "sample_callers",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(
            f"{r['address']},{r['name']},named_callers={r['named_caller_count']},"
            f"xrefs={r['xrefs_to_count']},named_callees={r['named_callee_count']},"
            f"calls={r['call_insn_count']},ns={r['namespace']}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
