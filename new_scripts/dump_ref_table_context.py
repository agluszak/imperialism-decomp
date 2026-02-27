#!/usr/bin/env python3
"""
Dump references to target addresses and nearby pointer-table context.

Useful for thunk-island analysis where functions are referenced via data slots.

Usage:
  .venv/bin/python new_scripts/dump_ref_table_context.py \
    [--window 4] [--max-refs 200] <addr_or_csv> [addr_or_csv...]

Inputs:
  - hex addresses (0x005649a0)
  - CSV with one of columns: address | callee_addr | caller_addr
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


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def parse_inputs(tokens: list[str]) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()

    def add(v: int):
        if v not in seen:
            seen.add(v)
            out.append(v)

    for token in tokens:
        p = Path(token)
        if p.exists() and p.suffix.lower() == ".csv":
            with p.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    raw = (
                        (row.get("address") or "").strip()
                        or (row.get("callee_addr") or "").strip()
                        or (row.get("caller_addr") or "").strip()
                    )
                    if not raw:
                        continue
                    try:
                        add(parse_hex(raw))
                    except Exception:
                        continue
            continue
        add(parse_hex(token))
    return out


def fmt_func_name(f) -> str:
    if f is None:
        return "<none>"
    return f"{f.getEntryPoint()} {f.getName()}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=4, help="Entries before/after data slot")
    ap.add_argument("--max-refs", type=int, default=200, help="Max refs printed per target")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument("inputs", nargs="+", help="Addresses or CSV files")
    args = ap.parse_args()

    targets = parse_inputs(args.inputs)
    if not targets:
        print("no addresses parsed")
        return 1

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        st = program.getSymbolTable()
        listing = program.getListing()
        mem = program.getMemory()

        for t in targets:
            addr = af.getAddress(f"0x{t:08x}")
            f = fm.getFunctionAt(addr)
            print(f"\n=== target 0x{t:08x} {f.getName() if f else '<no-func>'} ===")
            refs = list(rm.getReferencesTo(addr))
            print(f"refs_total={len(refs)}")

            shown = 0
            for r in refs:
                if shown >= args.max_refs:
                    break
                shown += 1
                fr = r.getFromAddress()
                cf = fm.getFunctionContaining(fr)
                ins = listing.getInstructionAt(fr)
                print(
                    f"  ref from={fr} type={r.getReferenceType()} func={fmt_func_name(cf)} "
                    f"ins={ins if ins is not None else '<no-inst>'}"
                )

                # Show data-slot neighborhood for data refs.
                if r.getReferenceType().isData():
                    sym = st.getPrimarySymbol(fr)
                    print(
                        f"    data-slot sym={sym.getName() if sym is not None else '<none>'} "
                        f"window={args.window}"
                    )
                    base_int = int(str(fr), 16)
                    for idx in range(-args.window, args.window + 1):
                        slot_int = base_int + idx * 4
                        slot = af.getAddress(f"0x{slot_int:08x}")
                        ps = st.getPrimarySymbol(slot)
                        lbl = ps.getName() if ps is not None else ""
                        try:
                            val = mem.getInt(slot) & 0xFFFFFFFF
                            tf = fm.getFunctionAt(af.getAddress(f"0x{val:08x}"))
                            tname = tf.getName() if tf is not None else ""
                            print(
                                f"      {slot} {lbl:28} -> 0x{val:08x} {tname}"
                            )
                        except Exception as ex:
                            print(f"      {slot} {lbl:28} -> <err> {ex}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

