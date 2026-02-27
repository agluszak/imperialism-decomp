#!/usr/bin/env python3
"""
List default-named methods (FUN_/thunk_FUN_) inside selected class namespaces.

Outputs triage CSV with caller/callee pressure to prioritize low-risk renames.

Usage:
  .venv/bin/python new_scripts/list_class_default_methods.py \
    --classes TViewMgr TGreatPower TAutoGreatPower TNewGameCommand \
    --out-csv tmp_decomp/class_default_methods.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
RX_DEFAULT = re.compile(r"^(FUN_|thunk_FUN_)")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def is_generic(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", nargs="+", required=True)
    ap.add_argument("--out-csv", default="tmp_decomp/class_default_methods.csv")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    classes = set(args.classes)
    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()
            if ns_name not in classes:
                continue
            if not RX_DEFAULT.match(f.getName()):
                continue

            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            named_callee = set()
            generic_callee = set()
            call_count = 0

            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                if str(ins.getMnemonicString()).upper() != "CALL":
                    continue
                call_count += 1
                for ref in ins.getReferencesFrom():
                    c = fm.getFunctionAt(ref.getToAddress())
                    if c is None:
                        continue
                    ep = str(c.getEntryPoint())
                    if ep.startswith("EXTERNAL:"):
                        continue
                    tag = f"{c.getName()}@{ep}"
                    if is_generic(c.getName()):
                        generic_callee.add(tag)
                    else:
                        named_callee.add(tag)

            named_callers = set()
            generic_callers = set()
            refs_to = rm.getReferencesTo(f.getEntryPoint())
            for ref in refs_to:
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                tag = f"{caller.getName()}@{caller.getEntryPoint()}"
                if is_generic(caller.getName()):
                    generic_callers.add(tag)
                else:
                    named_callers.add(tag)

            rows.append(
                {
                    "class_name": ns_name,
                    "address": f"0x{addr:08x}",
                    "name": f.getName(),
                    "instruction_count": str(int(f.getBody().getNumAddresses())),
                    "call_count": str(call_count),
                    "named_caller_count": str(len(named_callers)),
                    "generic_caller_count": str(len(generic_callers)),
                    "named_callee_count": str(len(named_callee)),
                    "generic_callee_count": str(len(generic_callee)),
                    "named_callers": ";".join(sorted(named_callers)[:16]),
                    "named_callees": ";".join(sorted(named_callee)[:16]),
                }
            )

    rows.sort(
        key=lambda r: (
            -int(r["named_callee_count"]),
            -int(r["named_caller_count"]),
            -int(r["call_count"]),
            r["class_name"],
            r["address"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "class_name",
                "address",
                "name",
                "instruction_count",
                "call_count",
                "named_caller_count",
                "generic_caller_count",
                "named_callee_count",
                "generic_callee_count",
                "named_callers",
                "named_callees",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(
            f"{r['class_name']},{r['address']},{r['name']},named_callees={r['named_callee_count']},"
            f"named_callers={r['named_caller_count']},calls={r['call_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
