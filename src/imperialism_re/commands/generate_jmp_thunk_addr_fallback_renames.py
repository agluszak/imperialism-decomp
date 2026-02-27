#!/usr/bin/env python3
"""
Generate rename CSV for generic single-JMP thunk functions with address fallback.

Targets:
  - existing functions only
  - source name matches regex (default: ^thunk_FUN_)
  - body is exactly one JMP to an internal function

Naming:
  - if target is named (non-generic): thunk_<TargetName>_At<SrcAddr>
  - if target is generic:            thunk_Target_<TargetAddr>_At<SrcAddr>

Output CSV columns:
  address,new_name,comment,old_name,target_name,target_addr,target_is_generic
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "UnknownTarget"
    if s[0].isdigit():
        s = "_" + s
    return s

def is_generic(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x00400000")
    ap.add_argument("--end", default="0x00700000")
    ap.add_argument("--name-regex", default=r"^thunk_FUN_")
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/jmp_thunk_addr_fallback_renames.csv",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    name_re = re.compile(args.name_regex)
    out_csv = Path(args.out_csv).resolve()
    root = resolve_project_root(args.project_root)

    rows: list[dict[str, str]] = []

    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        existing_names = set()
        fit = fm.getFunctions(True)
        funcs = []
        while fit.hasNext():
            f = fit.next()
            funcs.append(f)
            existing_names.add(f.getName())
        used_names = set(existing_names)

        for f in funcs:
            src_addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if src_addr < start or src_addr >= end:
                continue
            old_name = f.getName()
            if not name_re.search(old_name):
                continue

            ins_it = listing.getInstructions(f.getBody(), True)
            ins = []
            while ins_it.hasNext():
                ins.append(ins_it.next())
                if len(ins) > 2:
                    break
            if len(ins) != 1:
                continue
            if str(ins[0].getMnemonicString()).upper() != "JMP":
                continue

            flows = ins[0].getFlows()
            if flows is None or len(flows) != 1:
                continue

            target = fm.getFunctionAt(flows[0])
            if target is None:
                continue

            target_addr = target.getEntryPoint().getOffset() & 0xFFFFFFFF
            target_name = target.getName()
            target_generic = is_generic(target_name)
            if target_generic:
                base = f"thunk_Target_{target_addr:08x}_At{src_addr:08x}"
            else:
                base = f"thunk_{sanitize_symbol_name(target_name)}_At{src_addr:08x}"

            new_name = base
            i = 2
            while new_name in used_names:
                new_name = f"{base}_{i}"
                i += 1
            if new_name == old_name:
                continue
            used_names.add(new_name)

            rows.append(
                {
                    "address": f"0x{src_addr:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[ThunkJmp] single-JMP thunk to {target_name}"
                        f"@0x{target_addr:08x}"
                    ),
                    "old_name": old_name,
                    "target_name": target_name,
                    "target_addr": f"0x{target_addr:08x}",
                    "target_is_generic": "1" if target_generic else "0",
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
                "target_name",
                "target_addr",
                "target_is_generic",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    generic_targets = sum(1 for r in rows if r["target_is_generic"] == "1")
    print(
        f"[saved] {out_csv} rows={len(rows)} generic_target_rows={generic_targets} "
        f"range=0x{start:08x}-0x{end:08x} name_regex={args.name_regex}"
    )
    for r in rows[:120]:
        print(
            f"{r['address']},{r['old_name']} -> {r['new_name']},"
            f"target={r['target_name']}@{r['target_addr']}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
