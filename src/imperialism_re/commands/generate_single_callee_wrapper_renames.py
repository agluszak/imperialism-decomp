#!/usr/bin/env python3
"""
Generate conservative wrapper-style renames for small functions that call one named callee.

This is intended to convert unresolved/hint names to concrete wrapper names without guessing
gameplay semantics. It only renames when the body shape is tiny and callee evidence is clear.

Output CSV columns:
  address,new_name,comment,old_name,callee_name,instr_count,call_insn_count,unique_internal_callees

Usage:
  uv run impk generate_single_callee_wrapper_renames \
    --out-csv tmp_decomp/wrapper_single_callee_batch.csv \
    --name-regex "^(FUN_|Cluster_.*Hint_)" \
    --callee-regex "(Map|Tile|Nation|Turn|Trade|Diplom|Civilian|Army|Navy|Battle|Tactical)" \
    --exclude-callee-regex "(Ui|Dialog|Window|Picture|Resource|Bitmap|Cursor|Mfc|CWnd)"
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def sanitize_symbol_name(text: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_]", "_", text)
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        return "UnknownTarget"
    if out[0].isdigit():
        out = "_" + out
    return out

def is_generic(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/wrapper_single_callee_candidates.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--name-regex",
        default=r"^(FUN_|Cluster_.*Hint_)",
        help="Function name regex to consider",
    )
    ap.add_argument(
        "--callee-regex",
        default=r"",
        help="Optional regex required on chosen callee name",
    )
    ap.add_argument(
        "--exclude-callee-regex",
        default=r"",
        help="Optional regex that rejects chosen callee name",
    )
    ap.add_argument(
        "--max-instructions",
        type=int,
        default=26,
        help="Maximum instruction count in function body",
    )
    ap.add_argument(
        "--max-call-insns",
        type=int,
        default=2,
        help="Maximum CALL instructions in function body",
    )
    ap.add_argument(
        "--require-single-internal-callee",
        action="store_true",
        default=True,
        help="Require exactly one unique internal callee target",
    )
    ap.add_argument(
        "--addr-min",
        default="",
        help="Optional minimum function entry address (hex)",
    )
    ap.add_argument(
        "--addr-max",
        default="",
        help="Optional maximum function entry address (hex, inclusive)",
    )
    args = ap.parse_args()

    out_csv = Path(args.out_csv)
    root = resolve_project_root(args.project_root)
    name_re = re.compile(args.name_regex)
    callee_re = re.compile(args.callee_regex) if args.callee_regex else None
    exclude_callee_re = re.compile(args.exclude_callee_regex) if args.exclude_callee_regex else None
    addr_min = parse_hex(args.addr_min) if args.addr_min else None
    addr_max = parse_hex(args.addr_max) if args.addr_max else None

    rows = []

    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr_min is not None and addr < addr_min:
                continue
            if addr_max is not None and addr > addr_max:
                continue
            old_name = f.getName()
            if not name_re.search(old_name):
                continue

            instr_count = 0
            call_insn_count = 0
            internal_call_counter = Counter()

            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                instr_count += 1
                if instr_count > args.max_instructions:
                    break

                if str(ins.getMnemonicString()).upper() != "CALL":
                    continue
                call_insn_count += 1
                if call_insn_count > args.max_call_insns:
                    break

                refs = ins.getReferencesFrom()
                for ref in refs:
                    callee = fm.getFunctionAt(ref.getToAddress())
                    if callee is None:
                        continue
                    ep_txt = str(callee.getEntryPoint())
                    if ep_txt.startswith("EXTERNAL:"):
                        continue
                    callee_name = callee.getName()
                    if is_generic(callee_name):
                        continue
                    internal_call_counter[callee_name] += 1

            if instr_count == 0 or instr_count > args.max_instructions:
                continue
            if call_insn_count == 0 or call_insn_count > args.max_call_insns:
                continue
            if not internal_call_counter:
                continue

            unique_internal = len(internal_call_counter)
            if args.require_single_internal_callee and unique_internal != 1:
                continue

            chosen_callee, chosen_hits = max(
                internal_call_counter.items(), key=lambda kv: kv[1]
            )

            if callee_re and not callee_re.search(chosen_callee):
                continue
            if exclude_callee_re and exclude_callee_re.search(chosen_callee):
                continue

            safe_callee = sanitize_symbol_name(chosen_callee)
            new_name = f"WrapperFor_{safe_callee}_At{addr:08x}"
            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[WrapperShape] small wrapper around {chosen_callee}; "
                        f"instructions={instr_count}, call_insns={call_insn_count}, "
                        f"internal_calls={chosen_hits}, unique_internal={unique_internal}"
                    ),
                    "old_name": old_name,
                    "callee_name": chosen_callee,
                    "instr_count": str(instr_count),
                    "call_insn_count": str(call_insn_count),
                    "unique_internal_callees": str(unique_internal),
                }
            )

    rows.sort(key=lambda r: r["address"])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "new_name",
                "comment",
                "old_name",
                "callee_name",
                "instr_count",
                "call_insn_count",
                "unique_internal_callees",
            ],
        )
        wr.writeheader()
        wr.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(
            f"{r['address']},{r['old_name']} -> {r['new_name']},"
            f"callee={r['callee_name']},ins={r['instr_count']},calls={r['call_insn_count']}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
