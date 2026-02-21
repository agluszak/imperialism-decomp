#!/usr/bin/env python3
"""
Generate unresolved FUN_* callee candidates from caller-name regex.

Usage:
  .venv/bin/python new_scripts/generate_fun_callee_candidates.py <caller_regex> [out_csv] [project_root]

Output CSV columns:
  callee_addr,callee_name,total_calls,unique_callers,caller_names
"""

from __future__ import annotations

import csv
import re
import sys
from collections import Counter, defaultdict
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


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: generate_fun_callee_candidates.py <caller_regex> [out_csv] [project_root]"
        )
        return 1

    caller_regex = re.compile(sys.argv[1])
    out_csv = (
        Path(sys.argv[2])
        if len(sys.argv) >= 3
        else Path("tmp_decomp/fun_callee_candidates.csv")
    )
    root = Path(sys.argv[3]) if len(sys.argv) >= 4 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        callers = []
        it = fm.getFunctions(True)
        while it.hasNext():
            func = it.next()
            if caller_regex.search(func.getName()):
                callers.append(func)

        counts = Counter()
        from_names = defaultdict(set)

        for caller in callers:
            ins_it = listing.getInstructions(caller.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                if not str(ins).startswith("CALL "):
                    continue
                refs = ins.getReferencesFrom()
                try:
                    ref_iter = refs
                except Exception:
                    ref_iter = []
                for ref in ref_iter:
                    callee = fm.getFunctionAt(ref.getToAddress())
                    if callee is None:
                        continue
                    ep_txt = str(callee.getEntryPoint())
                    if ep_txt.startswith("EXTERNAL:"):
                        continue
                    try:
                        ep_int = int(ep_txt, 16)
                    except Exception:
                        continue
                    callee_name = callee.getName()
                    if not callee_name.startswith("FUN_"):
                        continue
                    counts[(ep_int, callee_name)] += 1
                    from_names[(ep_int, callee_name)].add(caller.getName())

    rows = []
    for (ep_int, callee_name), total_calls in counts.items():
        names = sorted(from_names[(ep_int, callee_name)])
        rows.append(
            {
                "callee_addr": f"0x{ep_int:08x}",
                "callee_name": callee_name,
                "total_calls": total_calls,
                "unique_callers": len(names),
                "caller_names": ";".join(names),
            }
        )

    rows.sort(key=lambda row: (-int(row["total_calls"]), -int(row["unique_callers"]), row["callee_addr"]))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "callee_addr",
                "callee_name",
                "total_calls",
                "unique_callers",
                "caller_names",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[saved] {out_csv} callers={len(callers)} candidates={len(rows)}")
    for row in rows[:80]:
        print(
            f"{row['callee_addr']},{row['callee_name']},"
            f"calls={row['total_calls']},callers={row['unique_callers']},"
            f"{row['caller_names']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
