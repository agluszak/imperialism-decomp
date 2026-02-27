#!/usr/bin/env python3
"""
Dump a table of dword values from memory.

Usage:
  .venv/bin/python new_scripts/dump_dword_table.py <addr_hex> [count]

Output:
  index,address,value_dec,value_hex
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


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: dump_dword_table.py <addr_hex> [count]")
        return 1

    base = parse_hex(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) >= 3 else 32
    root = Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()
        print("index,address,value_dec,value_hex")
        for i in range(count):
            addr_int = base + i * 4
            addr = af.getAddress(f"0x{addr_int:08x}")
            val = mem.getInt(addr)
            uval = val & 0xFFFFFFFF
            print(f"{i},0x{addr_int:08x},{val},0x{uval:08x}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
