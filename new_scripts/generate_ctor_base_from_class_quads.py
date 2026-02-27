#!/usr/bin/env python3
"""
Generate constructor rename CSV from class-quad rows (ctor-only, strict gates).

Input CSV columns:
  type_name,...,ctor,...

Output CSV columns:
  address,new_name,comment

Safety gates:
  - function still has generic name (FUN_/thunk_FUN_)
  - no AllocateWithFallbackHandler call inside function
  - function starts with a direct vtable-like store:
      MOV dword ptr [REG],0x00xxxxxx
    in the first few instructions
  - function size kept conservative

Usage:
  .venv/bin/python new_scripts/generate_ctor_base_from_class_quads.py \
    <input_csv> <output_csv> [project_root]
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

VTBL_MOV_RE = re.compile(r"^MOV dword ptr \[[A-Z]{2,3}\],0x00[0-9A-Fa-f]{6}$")


def parse_hex(text: str) -> int:
    t = text.strip()
    if not t:
        raise ValueError("empty address")
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def is_generic_name(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def first_n_instruction_strings(listing, func, n: int = 10) -> list[str]:
    out: list[str] = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext() and len(out) < n:
        out.append(str(it.next()))
    return out


def called_function_names(listing, fm, func) -> list[str]:
    out: list[str] = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        ins = it.next()
        if str(ins.getMnemonicString()).upper() != "CALL":
            continue
        refs = ins.getReferencesFrom()
        for ref in refs:
            callee = fm.getFunctionAt(ref.getToAddress())
            if callee is not None:
                out.append(callee.getName())
    return out


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) < 2:
        print(
            "usage: generate_ctor_base_from_class_quads.py "
            "<input_csv> <output_csv> [project_root]"
        )
        return 1

    in_csv = Path(argv[0])
    out_csv = Path(argv[1])
    root = Path(argv[2]) if len(argv) >= 3 else Path(__file__).resolve().parents[1]

    if not in_csv.exists():
        print(f"missing input csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        print("no input rows")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        name_to_addr = {}
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            n = f.getName()
            if n not in name_to_addr:
                name_to_addr[n] = f.getEntryPoint().getOffset()

        out_rows = []
        seen_addrs = set()
        seen_names = set()
        stats = {
            "rows": len(rows),
            "ctor_cells": 0,
            "emit": 0,
            "skip_missing": 0,
            "skip_non_generic": 0,
            "skip_alloc_call": 0,
            "skip_no_vtbl_store": 0,
            "skip_size": 0,
            "skip_collision": 0,
        }

        for row in rows:
            tname = (row.get("type_name") or "").strip()
            ctor_addr = (row.get("ctor") or "").strip()
            if not tname or not ctor_addr:
                continue
            stats["ctor_cells"] += 1

            try:
                off = parse_hex(ctor_addr)
                addr = af.getAddress(f"0x{off:08x}")
            except Exception:
                stats["skip_missing"] += 1
                continue

            func = fm.getFunctionAt(addr)
            if func is None:
                stats["skip_missing"] += 1
                continue

            if not is_generic_name(func.getName()):
                stats["skip_non_generic"] += 1
                continue

            if func.getBody().getNumAddresses() > 260:
                stats["skip_size"] += 1
                continue

            call_names = called_function_names(listing, fm, func)
            if any("AllocateWithFallbackHandler" in n for n in call_names):
                stats["skip_alloc_call"] += 1
                continue

            first_ins = first_n_instruction_strings(listing, func, 12)
            if not any(VTBL_MOV_RE.match(ins) for ins in first_ins):
                stats["skip_no_vtbl_store"] += 1
                continue

            new_name = f"Construct{tname}BaseState"
            if off in seen_addrs or new_name in seen_names:
                stats["skip_collision"] += 1
                continue
            existing = name_to_addr.get(new_name)
            if existing is not None and existing != off:
                stats["skip_collision"] += 1
                continue

            seen_addrs.add(off)
            seen_names.add(new_name)
            out_rows.append(
                {
                    "address": f"0x{off:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[ClassQuad] ctor inferred for {tname}; "
                        "neighbor-quad plus direct vtable store pattern."
                    ),
                }
            )
            stats["emit"] += 1

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(out_rows)

    print(f"[done] output_rows={len(out_rows)} -> {out_csv}")
    for k in sorted(stats):
        print(f"  {k}={stats[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
