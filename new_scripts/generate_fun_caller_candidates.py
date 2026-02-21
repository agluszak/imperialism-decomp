#!/usr/bin/env python3
"""
Generate unresolved FUN_* caller candidates for callees matched by regex.

Usage:
  .venv/bin/python new_scripts/generate_fun_caller_candidates.py <callee_regex> [out_csv] [project_root]

Output CSV columns:
  caller_addr,caller_name,total_hits,unique_callees,callee_names
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
            "usage: generate_fun_caller_candidates.py <callee_regex> [out_csv] [project_root]"
        )
        return 1

    callee_regex = re.compile(sys.argv[1])
    out_csv = (
        Path(sys.argv[2])
        if len(sys.argv) >= 3
        else Path("tmp_decomp/fun_caller_candidates.csv")
    )
    root = Path(sys.argv[3]) if len(sys.argv) >= 4 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        matched_callees = []
        it = fm.getFunctions(True)
        while it.hasNext():
            func = it.next()
            if callee_regex.search(func.getName()):
                matched_callees.append(func)

        counts = Counter()
        callee_set = defaultdict(set)

        for callee in matched_callees:
            callee_name = callee.getName()
            callee_ep_txt = str(callee.getEntryPoint())
            if callee_ep_txt.startswith("EXTERNAL:"):
                continue
            callee_ep = int(callee_ep_txt, 16)
            refs = rm.getReferencesTo(af.getAddress(f"0x{callee_ep:08x}"))
            for ref in refs:
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                caller_name = caller.getName()
                if not caller_name.startswith("FUN_"):
                    continue
                caller_ep_txt = str(caller.getEntryPoint())
                if caller_ep_txt.startswith("EXTERNAL:"):
                    continue
                try:
                    caller_ep = int(caller_ep_txt, 16)
                except Exception:
                    continue
                counts[(caller_ep, caller_name)] += 1
                callee_set[(caller_ep, caller_name)].add(callee_name)

    rows = []
    for (caller_ep, caller_name), total_hits in counts.items():
        names = sorted(callee_set[(caller_ep, caller_name)])
        rows.append(
            {
                "caller_addr": f"0x{caller_ep:08x}",
                "caller_name": caller_name,
                "total_hits": total_hits,
                "unique_callees": len(names),
                "callee_names": ";".join(names),
            }
        )

    rows.sort(
        key=lambda row: (
            -int(row["unique_callees"]),
            -int(row["total_hits"]),
            row["caller_addr"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "caller_addr",
                "caller_name",
                "total_hits",
                "unique_callees",
                "callee_names",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[saved] {out_csv} matched_callees={len(matched_callees)} candidates={len(rows)}")
    for row in rows[:80]:
        print(
            f"{row['caller_addr']},{row['caller_name']},"
            f"hits={row['total_hits']},callees={row['unique_callees']},"
            f"{row['callee_names']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
