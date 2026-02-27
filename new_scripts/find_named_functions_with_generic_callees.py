#!/usr/bin/env python3
"""
Find named functions that still call generic helpers (FUN_/Cluster_/WrapperFor_Cluster_).

Usage:
  .venv/bin/python new_scripts/find_named_functions_with_generic_callees.py \
    <caller_regex> [out_csv] [project_root]

Output CSV columns:
  caller_addr,caller_name,generic_callee_count,generic_callees
"""

from __future__ import annotations

import csv
import re
import sys
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


def is_generic_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: find_named_functions_with_generic_callees.py "
            "<caller_regex> [out_csv] [project_root]"
        )
        return 1

    caller_regex = re.compile(sys.argv[1])
    out_csv = (
        Path(sys.argv[2])
        if len(sys.argv) >= 3
        else Path("tmp_decomp/named_functions_with_generic_callees.csv")
    )
    root = Path(sys.argv[3]) if len(sys.argv) >= 4 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        it = fm.getFunctions(True)
        while it.hasNext():
            caller = it.next()
            caller_name = caller.getName()
            if caller_name.startswith("FUN_"):
                continue
            if not caller_regex.search(caller_name):
                continue

            generic: set[str] = set()
            ins_it = listing.getInstructions(caller.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                if not str(ins).startswith("CALL "):
                    continue
                refs = ins.getReferencesFrom()
                for ref in refs:
                    callee = fm.getFunctionAt(ref.getToAddress())
                    if callee is None:
                        continue
                    callee_name = callee.getName()
                    if is_generic_name(callee_name):
                        generic.add(f"{callee_name}@{callee.getEntryPoint()}")

            if generic:
                rows.append(
                    {
                        "caller_addr": str(caller.getEntryPoint()),
                        "caller_name": caller_name,
                        "generic_callee_count": str(len(generic)),
                        "generic_callees": ";".join(sorted(generic)),
                    }
                )

    rows.sort(
        key=lambda r: (
            -int(r["generic_callee_count"]),
            r["caller_name"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "caller_addr",
                "caller_name",
                "generic_callee_count",
                "generic_callees",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for row in rows[:120]:
        print(
            f"{row['caller_addr']},{row['caller_name']},"
            f"generic={row['generic_callee_count']},{row['generic_callees']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
