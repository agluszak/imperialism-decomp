#!/usr/bin/env python3
"""
Generate neutral implementation names for FUN_* targets referenced by named JMP thunks.

Selection:
  - source function name matches --thunk-name-regex (default: ^thunk_)
  - source body is exactly one JMP to internal target function
  - target currently named FUN_*

Output:
  address,new_name,comment,old_name,thunk_count,sample_thunks

Name format:
  ThunkTargetImpl_<target_addr_hex>
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x00400000")
    ap.add_argument("--end", default="0x00700000")
    ap.add_argument("--thunk-name-regex", default=r"^thunk_")
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/fun_impl_names_from_thunk_targets.csv",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    thunk_re = re.compile(args.thunk_name_regex)
    out_csv = Path(args.out_csv).resolve()
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        existing_names = set()
        fit = fm.getFunctions(True)
        funcs = []
        while fit.hasNext():
            f = fit.next()
            funcs.append(f)
            existing_names.add(f.getName())
        used_names = set(existing_names)

        target_to_thunks: dict[int, list[str]] = defaultdict(list)

        for f in funcs:
            src_addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if src_addr < start or src_addr >= end:
                continue
            src_name = f.getName()
            if not thunk_re.search(src_name):
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
            tgt_func = fm.getFunctionAt(flows[0])
            if tgt_func is None:
                continue
            tgt_name = tgt_func.getName()
            if not tgt_name.startswith("FUN_"):
                continue
            tgt_addr = tgt_func.getEntryPoint().getOffset() & 0xFFFFFFFF
            target_to_thunks[tgt_addr].append(src_name)

        for tgt_addr in sorted(target_to_thunks):
            tgt_func = fm.getFunctionAt(af.getAddress(f"0x{tgt_addr:08x}"))
            if tgt_func is None:
                continue
            old_name = tgt_func.getName()
            if not old_name.startswith("FUN_"):
                continue

            base = f"ThunkTargetImpl_{tgt_addr:08x}"
            new_name = base
            i = 2
            while new_name in used_names:
                new_name = f"{base}_{i}"
                i += 1
            if new_name == old_name:
                continue
            used_names.add(new_name)

            sample = ";".join(sorted(target_to_thunks[tgt_addr])[:4])
            rows.append(
                {
                    "address": f"0x{tgt_addr:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[ThunkTargetImpl] FUN target of named JMP thunk(s); "
                        f"count={len(target_to_thunks[tgt_addr])}"
                    ),
                    "old_name": old_name,
                    "thunk_count": str(len(target_to_thunks[tgt_addr])),
                    "sample_thunks": sample,
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
                "thunk_count",
                "sample_thunks",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"range=0x{start:08x}-0x{end:08x} thunk_regex={args.thunk_name_regex}"
    )
    for r in rows[:120]:
        print(
            f"{r['address']},{r['old_name']} -> {r['new_name']},"
            f"thunks={r['thunk_count']},sample={r['sample_thunks']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
