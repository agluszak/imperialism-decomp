#!/usr/bin/env python3
"""
Scan decompiled functions for hidden-parameter artifacts.

Artifacts detected:
  - `in_ECX`
  - `in_stack_XXXXXXXX`

Use this as a gate report after ABI/signature waves.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

STACK_RE = re.compile(r"\bin_stack_([0-9a-fA-F]{8})\b")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        required=True,
        help="Output CSV path",
    )
    ap.add_argument(
        "--name-regex",
        default=r"(Map|Turn|Startup|Application|ViewMgr|MacViewMgr)",
        help="Function name regex filter",
    )
    ap.add_argument(
        "--class-regex",
        default=r"^(TMap|TViewMgr|TApplication|TAmbitApplication|TMacViewMgr|TWorldView|TAssetMgr|TArmyMgr|TCivMgr)",
        help="Class namespace regex filter",
    )
    ap.add_argument("--addr-min", default="", help="Optional min function address (hex)")
    ap.add_argument("--addr-max", default="", help="Optional max function address (hex)")
    ap.add_argument("--max-functions", type=int, default=0, help="Optional cap (0 = unlimited)")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    name_re = re.compile(args.name_regex)
    class_re = re.compile(args.class_regex)
    addr_min = parse_hex(args.addr_min) if args.addr_min else None
    addr_max = parse_hex(args.addr_max) if args.addr_max else None

    rows = []
    scanned = 0

    with open_program(root) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        ifc = DecompInterface()
        ifc.openProgram(program)

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr_min is not None and addr < addr_min:
                continue
            if addr_max is not None and addr > addr_max:
                continue

            fn = f.getName()
            ns = f.getParentNamespace()
            ns_name = "" if ns is None or ns == global_ns else ns.getName()

            if not name_re.search(fn):
                if not (ns_name and class_re.search(ns_name)):
                    continue

            scanned += 1
            if args.max_functions > 0 and scanned > args.max_functions:
                break

            res = ifc.decompileFunction(f, 20, None)
            if not res or not res.decompileCompleted():
                continue
            c_code = res.getDecompiledFunction().getC()
            ecx_hits = c_code.count("in_ECX")
            stack_arg_hits = 0
            stack_local_hits = 0
            stack_arg_slots = set()
            stack_local_slots = set()
            for m in STACK_RE.findall(c_code):
                raw = int(m, 16)
                if raw < 0x80000000:
                    stack_arg_hits += 1
                    stack_arg_slots.add(raw)
                else:
                    stack_local_hits += 1
                    stack_local_slots.add(raw)

            if ecx_hits == 0 and stack_arg_hits == 0 and stack_local_hits == 0:
                continue

            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "name": fn,
                    "namespace": ns_name,
                    "signature": str(f.getSignature()),
                    "in_ecx_hits": str(ecx_hits),
                    "in_stack_arg_hits": str(stack_arg_hits),
                    "in_stack_local_hits": str(stack_local_hits),
                    "in_stack_arg_slots": str(len(stack_arg_slots)),
                    "in_stack_local_slots": str(len(stack_local_slots)),
                    "max_stack_arg_slot": (
                        f"0x{max(stack_arg_slots):08x}" if stack_arg_slots else ""
                    ),
                    "stack_arg_slot_list": ";".join(
                        f"0x{x:08x}" for x in sorted(stack_arg_slots)
                    ),
                }
            )

    rows.sort(
        key=lambda r: (
            -int(r["in_stack_arg_hits"]),
            -int(r["in_ecx_hits"]),
            -int(r["in_stack_local_hits"]),
            r["address"],
        )
    )
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "name",
                "namespace",
                "signature",
                "in_ecx_hits",
                "in_stack_arg_hits",
                "in_stack_local_hits",
                "in_stack_arg_slots",
                "in_stack_local_slots",
                "max_stack_arg_slot",
                "stack_arg_slot_list",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)} scanned={scanned}")
    print(f"[summary] in_ecx_total={sum(int(r['in_ecx_hits']) for r in rows)}")
    print(f"[summary] in_stack_arg_total={sum(int(r['in_stack_arg_hits']) for r in rows)}")
    print(f"[summary] in_stack_local_total={sum(int(r['in_stack_local_hits']) for r in rows)}")
    print(f"[summary] in_stack_arg_unique_slots_total={sum(int(r['in_stack_arg_slots']) for r in rows)}")
    for r in rows[:120]:
        print(
            f"{r['address']},{r['namespace']}::{r['name']},"
            f"in_ECX={r['in_ecx_hits']},in_stack_arg={r['in_stack_arg_hits']},"
            f"in_stack_arg_slots={r['in_stack_arg_slots']},"
            f"in_stack_local={r['in_stack_local_hits']}"
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
