#!/usr/bin/env python3
"""
Scan initialized memory for dword values that fall in a target address range.

Useful for finding indirect pointers/tables to a code/data lane when direct xrefs are absent.

Usage:
  .venv/bin/python new_scripts/inventory_data_dword_values_in_range.py \
    --addr-min 0x0066d9f0 --addr-max 0x0066da18 \
    --out-csv tmp_decomp/data_ptr_hits.csv
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


def in_range(v: int, lo: int, hi: int) -> bool:
    return lo <= v <= hi


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr-min", required=True)
    ap.add_argument("--addr-max", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    if hi < lo:
        lo, hi = hi, lo

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        mem = program.getMemory()
        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            bstart = block.getStart().getOffset() & 0xFFFFFFFF
            bend = block.getEnd().getOffset() & 0xFFFFFFFF
            addr_i = bstart
            while addr_i + 3 <= bend:
                addr = af.getAddress(f"0x{addr_i:08x}")
                try:
                    v = mem.getInt(addr) & 0xFFFFFFFF
                except Exception:
                    addr_i += 4
                    continue
                if in_range(v, lo, hi):
                    sym = st.getPrimarySymbol(addr)
                    sym_name = sym.getName() if sym is not None else ""

                    code_ref_count = 0
                    data_ref_count = 0
                    refs = rm.getReferencesTo(addr)
                    for ref in refs:
                        from_addr = ref.getFromAddress()
                        if from_addr is not None and fm.getFunctionContaining(from_addr) is not None:
                            code_ref_count += 1
                        else:
                            data_ref_count += 1

                    rows.append(
                        {
                            "slot_addr": f"0x{addr_i:08x}",
                            "slot_symbol": sym_name,
                            "slot_block": block.getName(),
                            "value_addr": f"0x{v:08x}",
                            "code_refs_to_slot": str(code_ref_count),
                            "data_refs_to_slot": str(data_ref_count),
                        }
                    )
                addr_i += 4

    rows.sort(key=lambda r: (r["slot_addr"], r["value_addr"]))
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_addr",
                "slot_symbol",
                "slot_block",
                "value_addr",
                "code_refs_to_slot",
                "data_refs_to_slot",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[done] out={out_csv} rows={len(rows)} range=0x{lo:08x}..0x{hi:08x}")
    for r in rows[:200]:
        print(
            f"{r['slot_addr']},{r['slot_symbol']},{r['slot_block']},"
            f"{r['value_addr']},code_refs={r['code_refs_to_slot']},data_refs={r['data_refs_to_slot']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
