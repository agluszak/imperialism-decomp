#!/usr/bin/env python3
"""
Inventory branch instructions whose source address is not inside any function.

This is used to recover residual tiny stubs and decode islands that are still
outside function boundaries.

Outputs:
  - <out-prefix>_detail.csv
  - <out-prefix>_summary.csv (grouped by inferred start)

Usage:
  uv run impk inventory_no_func_branch_sources \
    --out-prefix tmp_decomp/no_func_branch_sources

  # Focus only on unresolved-owner islands (true function-recovery candidates):
  uv run impk inventory_no_func_branch_sources \
    --owner-mode empty --out-prefix tmp_decomp/no_func_branch_sources_owner_empty
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

def flow_target_str(ins) -> str:
    try:
        flows = ins.getFlows()
        if flows is None or len(flows) != 1:
            return ""
        return str(flows[0])
    except Exception:
        return ""

def infer_start(listing, src_ins, max_back: int):
    cur = src_ins
    oldest = src_ins
    for _ in range(max_back):
        prev = listing.getInstructionBefore(cur.getAddress())
        if prev is None:
            break
        if str(prev.getMnemonicString()).upper() == "RET":
            return listing.getInstructionAfter(prev.getAddress())
        oldest = prev
        cur = prev
    return oldest

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/no_func_branch_sources",
        help="Output prefix (without suffix)",
    )
    ap.add_argument(
        "--mnemonics",
        default="CALL,JMP",
        help="Comma-separated branch mnemonics to include",
    )
    ap.add_argument(
        "--max-back",
        type=int,
        default=16,
        help="Max instructions to walk backwards for inferred start",
    )
    ap.add_argument(
        "--owner-mode",
        default="any",
        choices=["any", "empty", "nonempty"],
        help="Filter rows by inferred_start_owner",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    mnems = {m.strip().upper() for m in args.mnemonics.split(",") if m.strip()}
    out_prefix = Path(args.out_prefix).resolve()
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    out_detail = out_prefix.with_name(out_prefix.name + "_detail.csv")
    out_summary = out_prefix.with_name(out_prefix.name + "_summary.csv")

    root = resolve_project_root(args.project_root)

    detail_rows = []
    summary_counts = defaultdict(list)

    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        it = listing.getInstructions(True)
        while it.hasNext():
            ins = it.next()
            mnem = str(ins.getMnemonicString()).upper()
            if mnem not in mnems:
                continue
            src_addr = ins.getAddress()
            if fm.getFunctionContaining(src_addr) is not None:
                continue

            start_ins = infer_start(listing, ins, args.max_back)
            if start_ins is None:
                continue
            start_addr = start_ins.getAddress()
            start_owner = fm.getFunctionContaining(start_addr)
            start_owner_name = start_owner.getName() if start_owner is not None else ""

            tgt = flow_target_str(ins)
            target_name = ""
            if tgt:
                tf = fm.getFunctionAt(program.getAddressFactory().getAddress(tgt))
                if tf is not None:
                    target_name = tf.getName()

            row = {
                "source_addr": str(src_addr),
                "mnemonic": mnem,
                "instruction": str(ins),
                "target_addr": tgt,
                "target_name": target_name,
                "inferred_start": str(start_addr),
                "inferred_start_ins": str(start_ins),
                "inferred_start_owner": start_owner_name,
            }

            if args.owner_mode == "empty" and start_owner_name:
                continue
            if args.owner_mode == "nonempty" and not start_owner_name:
                continue

            detail_rows.append(row)
            summary_counts[str(start_addr)].append(row)

    detail_rows.sort(key=lambda r: int(r["source_addr"], 16))
    with out_detail.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "source_addr",
                "mnemonic",
                "instruction",
                "target_addr",
                "target_name",
                "inferred_start",
                "inferred_start_ins",
                "inferred_start_owner",
            ],
        )
        w.writeheader()
        w.writerows(detail_rows)

    summary_rows = []
    for start_addr, rows in summary_counts.items():
        rows_sorted = sorted(rows, key=lambda r: int(r["source_addr"], 16))
        targets = {}
        for r in rows_sorted:
            key = (r["target_addr"], r["target_name"])
            targets[key] = targets.get(key, 0) + 1
        top_targets = sorted(targets.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))[:5]
        summary_rows.append(
            {
                "inferred_start": start_addr,
                "branch_count": str(len(rows_sorted)),
                "inferred_start_ins": rows_sorted[0]["inferred_start_ins"],
                "inferred_start_owner": rows_sorted[0]["inferred_start_owner"],
                "first_source": rows_sorted[0]["source_addr"],
                "last_source": rows_sorted[-1]["source_addr"],
                "top_targets": ";".join(
                    f"{ta or '<none>'}:{tn or '<none>'}:{cnt}" for (ta, tn), cnt in top_targets
                ),
            }
        )

    summary_rows.sort(
        key=lambda r: (-int(r["branch_count"]), int(r["inferred_start"], 16), r["inferred_start"])
    )
    with out_summary.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "inferred_start",
                "branch_count",
                "inferred_start_ins",
                "inferred_start_owner",
                "first_source",
                "last_source",
                "top_targets",
            ],
        )
        w.writeheader()
        w.writerows(summary_rows)

    print(f"[saved] {out_detail} rows={len(detail_rows)}")
    print(f"[saved] {out_summary} rows={len(summary_rows)}")
    print(f"[owner_mode] {args.owner_mode}")
    for r in summary_rows[:20]:
        print(
            f"[stub] {r['inferred_start']} branches={r['branch_count']} "
            f"owner={r['inferred_start_owner'] or '<no_func>'} "
            f"targets={r['top_targets']}"
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
