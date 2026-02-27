#!/usr/bin/env python3
"""
Generate neutral implementation names for FUN_* targets referenced by named wrappers.

Wrapper detection:
  - source function name matches --wrapper-name-regex (default: ^WrapperFor_)
  - source shape is either:
      * single JMP target
      * CALL target ; RET
  - target currently named FUN_*

Output:
  address,new_name,comment,old_name,wrapper_count,sample_wrappers

Name format:
  WrapperTargetImpl_<target_addr_hex>
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def detect_forward_target(fm, listing, func):
    ins = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        ins.append(it.next())
        if len(ins) > 3:
            break
    if len(ins) == 1 and str(ins[0].getMnemonicString()).upper() == "JMP":
        flows = ins[0].getFlows()
        if flows is None or len(flows) != 1:
            return None
        return fm.getFunctionAt(flows[0])
    if (
        len(ins) == 2
        and str(ins[0].getMnemonicString()).upper() == "CALL"
        and str(ins[1].getMnemonicString()).upper() == "RET"
    ):
        refs = ins[0].getReferencesFrom()
        for ref in refs:
            callee = fm.getFunctionAt(ref.getToAddress())
            if callee is not None:
                ep_txt = str(callee.getEntryPoint())
                if not ep_txt.startswith("EXTERNAL:"):
                    return callee
    return None

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x00400000")
    ap.add_argument("--end", default="0x00700000")
    ap.add_argument("--wrapper-name-regex", default=r"^WrapperFor_")
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/fun_impl_names_from_wrapper_targets.csv",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    wrapper_re = re.compile(args.wrapper_name_regex)
    out_csv = Path(args.out_csv).resolve()
    root = resolve_project_root(args.project_root)

    rows: list[dict[str, str]] = []

    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        existing_names = set()
        funcs = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            funcs.append(f)
            existing_names.add(f.getName())
        used_names = set(existing_names)

        target_to_wrappers: dict[int, list[str]] = defaultdict(list)
        for src in funcs:
            src_addr = src.getEntryPoint().getOffset() & 0xFFFFFFFF
            if src_addr < start or src_addr >= end:
                continue
            src_name = src.getName()
            if not wrapper_re.search(src_name):
                continue
            tgt = detect_forward_target(fm, listing, src)
            if tgt is None:
                continue
            tgt_name = tgt.getName()
            if not tgt_name.startswith("FUN_"):
                continue
            tgt_addr = tgt.getEntryPoint().getOffset() & 0xFFFFFFFF
            target_to_wrappers[tgt_addr].append(src_name)

        for tgt_addr in sorted(target_to_wrappers):
            tgt_func = fm.getFunctionAt(af.getAddress(f"0x{tgt_addr:08x}"))
            if tgt_func is None:
                continue
            old_name = tgt_func.getName()
            if not old_name.startswith("FUN_"):
                continue

            base = f"WrapperTargetImpl_{tgt_addr:08x}"
            new_name = base
            i = 2
            while new_name in used_names:
                new_name = f"{base}_{i}"
                i += 1
            if new_name == old_name:
                continue
            used_names.add(new_name)

            sample = ";".join(sorted(target_to_wrappers[tgt_addr])[:4])
            rows.append(
                {
                    "address": f"0x{tgt_addr:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[WrapperTargetImpl] FUN target of named wrapper(s); "
                        f"count={len(target_to_wrappers[tgt_addr])}"
                    ),
                    "old_name": old_name,
                    "wrapper_count": str(len(target_to_wrappers[tgt_addr])),
                    "sample_wrappers": sample,
                }
            )

    rows.sort(key=lambda r: r["address"])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "new_name",
                "comment",
                "old_name",
                "wrapper_count",
                "sample_wrappers",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"range=0x{start:08x}-0x{end:08x} wrapper_regex={args.wrapper_name_regex}"
    )
    for r in rows[:120]:
        print(
            f"{r['address']},{r['old_name']} -> {r['new_name']},"
            f"wrappers={r['wrapper_count']},sample={r['sample_wrappers']}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
