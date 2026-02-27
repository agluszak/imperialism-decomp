#!/usr/bin/env python3
"""
Dump disassembly for one or more function entry addresses.

Usage:
  .venv/bin/python new_scripts/dump_function_disassembly.py <addr_hex> [addr_hex...]
"""

from __future__ import annotations

import sys
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
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
    if len(sys.argv) < 2:
        print("usage: dump_function_disassembly.py <addr_hex> [addr_hex...]")
        return 1

    targets = [parse_hex(a) for a in sys.argv[1:]]
    root = Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        for t in targets:
            addr = af.getAddress(f"0x{t:08x}")
            f = fm.getFunctionAt(addr)
            print(f"\n=== 0x{t:08x} ===")
            if f is None:
                print("function: <missing>")
                continue
            print(f"function: {f.getName()} :: {f.getSignature()}")
            ins_it = listing.getInstructions(f.getBody(), True)
            count = 0
            while ins_it.hasNext():
                ins = ins_it.next()
                print(f"{ins.getAddress()}: {ins}")
                count += 1
            print(f"instruction_count={count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
