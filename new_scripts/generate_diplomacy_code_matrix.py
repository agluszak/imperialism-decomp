#!/usr/bin/env python3
"""
Generate a diplomacy raw-code matrix from instruction-level constant usage.

Outputs CSV rows:
  function_addr,function_name,instruction_addr,mnemonic,raw_value,domain_hint,instruction

Default domains:
  relation: 2..6
  action: 0,1,10,13,60
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

REL_VALUES = {2, 3, 4, 5, 6}
ACT_VALUES = {0, 1, 10, 13, 60}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def domain_hint(v: int) -> str:
    in_rel = v in REL_VALUES
    in_act = v in ACT_VALUES
    if in_rel and in_act:
        return "REL_OR_ACT"
    if in_rel:
        return "REL"
    if in_act:
        return "ACT"
    return "OTHER"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/diplomacy_code_matrix.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--function-name-regex",
        default=r"(diplom|nationstatus|treaty|relation)",
        help="Case-insensitive regex for candidate function names",
    )
    ap.add_argument(
        "--mnemonics",
        default="CMP,PUSH",
        help="Comma-separated mnemonics to include",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    import re

    fn_re = re.compile(args.function_name_regex, re.IGNORECASE)
    mset = {m.strip().upper() for m in args.mnemonics.split(",") if m.strip()}
    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            if not fn_re.search(fn.getName()):
                continue
            ins_it = listing.getInstructions(fn.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                mnem = str(ins.getMnemonicString()).upper()
                if mnem not in mset:
                    continue
                for oi in range(ins.getNumOperands()):
                    sc = ins.getScalar(oi)
                    if sc is None:
                        continue
                    v = int(sc.getUnsignedValue()) & 0xFFFFFFFF
                    if v not in REL_VALUES and v not in ACT_VALUES:
                        continue
                    rows.append(
                        {
                            "function_addr": str(fn.getEntryPoint()),
                            "function_name": fn.getName(),
                            "instruction_addr": str(ins.getAddress()),
                            "mnemonic": mnem,
                            "raw_value": str(v),
                            "domain_hint": domain_hint(v),
                            "instruction": str(ins),
                        }
                    )
                    break

    rows.sort(
        key=lambda r: (
            r["function_name"].lower(),
            int(r["instruction_addr"], 16),
        )
    )

    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "function_addr",
                "function_name",
                "instruction_addr",
                "mnemonic",
                "raw_value",
                "domain_hint",
                "instruction",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[done] rows={len(rows)} out={out_csv}")
    for r in rows[:120]:
        print(
            f"{r['function_addr']} {r['function_name']} {r['instruction_addr']} "
            f"{r['mnemonic']} {r['raw_value']} {r['domain_hint']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

