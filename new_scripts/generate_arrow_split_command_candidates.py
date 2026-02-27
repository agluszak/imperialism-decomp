#!/usr/bin/env python3
"""
Find functions that reference arrow split-command IDs (100/101 = 0x64/0x65).

Outputs CSV columns:
  address,function_name,hit_100,hit_101,total_hits,both_ids,xrefs_to_count,
  named_callee_count,named_callees

Usage:
  .venv/bin/python new_scripts/generate_arrow_split_command_candidates.py \
    --out-csv tmp_decomp/batchNN_arrow_split_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
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


def is_generic(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_") or name.startswith("Cluster_")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/arrow_split_command_candidates.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--min-total-hits",
        type=int,
        default=1,
        help="Minimum total number of 100/101 immediate hits",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            hit_100 = 0
            hit_101 = 0
            named_callees = set()

            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                for oi in range(ins.getNumOperands()):
                    sc = ins.getScalar(oi)
                    if sc is None:
                        continue
                    try:
                        val = int(sc.getUnsignedValue())
                    except Exception:
                        continue
                    if val == 100:
                        hit_100 += 1
                    elif val == 101:
                        hit_101 += 1

                if str(ins.getMnemonicString()).upper() == "CALL":
                    refs = ins.getReferencesFrom()
                    for ref in refs:
                        cf = fm.getFunctionAt(ref.getToAddress())
                        if cf is None:
                            continue
                        cn = cf.getName()
                        if is_generic(cn):
                            continue
                        named_callees.add(cn)

            total_hits = hit_100 + hit_101
            if total_hits < args.min_total_hits:
                continue

            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            refs_to = rm.getReferencesTo(af.getAddress(f"0x{addr:08x}"))
            xrefs = 0
            seen_ref_funcs = set()
            for ref in refs_to:
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                caddr = caller.getEntryPoint().getOffset() & 0xFFFFFFFF
                if caddr in seen_ref_funcs:
                    continue
                seen_ref_funcs.add(caddr)
                xrefs += 1

            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "function_name": f.getName(),
                    "hit_100": str(hit_100),
                    "hit_101": str(hit_101),
                    "total_hits": str(total_hits),
                    "both_ids": "1" if hit_100 > 0 and hit_101 > 0 else "0",
                    "xrefs_to_count": str(xrefs),
                    "named_callee_count": str(len(named_callees)),
                    "named_callees": ";".join(sorted(named_callees)[:24]),
                }
            )

    rows.sort(
        key=lambda r: (
            -int(r["both_ids"]),
            -int(r["total_hits"]),
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
                "function_name",
                "hit_100",
                "hit_101",
                "total_hits",
                "both_ids",
                "xrefs_to_count",
                "named_callee_count",
                "named_callees",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(
            f"{r['address']},{r['function_name']},hits={r['total_hits']},"
            f"both={r['both_ids']},xrefs={r['xrefs_to_count']},callees={r['named_callees']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
