#!/usr/bin/env python3
"""
Generate rename CSV for existing generic single-JMP thunk functions.

Targets:
  - Existing functions only (no function creation)
  - Name matches generic regex (default: FUN_/thunk_FUN_)
  - Body is exactly one JMP
  - JMP target is an internal, already-named non-generic function

Output CSV columns:
  address,new_name,comment,old_name,target_name,target_addr

Usage:
  .venv/bin/python new_scripts/generate_existing_jmp_thunk_renames.py \
    --start 0x00400000 --end 0x00600000 \
    --out-csv tmp_decomp/existing_jmp_thunk_renames.csv
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
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x00400000", help="Start address (inclusive)")
    ap.add_argument("--end", default="0x00600000", help="End address (exclusive)")
    ap.add_argument(
        "--name-regex",
        default=r"^(FUN_|thunk_FUN_)",
        help="Regex for source function names",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/existing_jmp_thunk_renames.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    name_re = re.compile(args.name_regex)
    out_csv = Path(args.out_csv).resolve()
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        existing_names = set()
        fit = fm.getFunctions(True)
        funcs = []
        while fit.hasNext():
            f = fit.next()
            funcs.append(f)
            existing_names.add(f.getName())

        reserved_names = set(existing_names)

        for f in funcs:
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr < start or addr >= end:
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
            target_name = target.getName()
            if is_generic(target_name):
                continue

            base = f"thunk_{sanitize_symbol_name(target_name)}_At{addr:08x}"
            new_name = base
            i = 2
            while new_name in reserved_names:
                new_name = f"{base}_{i}"
                i += 1
            if new_name == old_name:
                continue
            reserved_names.add(new_name)

            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "new_name": new_name,
                    "comment": f"Single-JMP thunk to {target_name}",
                    "old_name": old_name,
                    "target_name": target_name,
                    "target_addr": str(target.getEntryPoint()),
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
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
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
