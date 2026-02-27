#!/usr/bin/env python3
"""
List references to one or more addresses with function/instruction context.

Usage:
  .venv/bin/python new_scripts/list_xrefs_to_address.py <addr_hex> [addr_hex...]

Output columns:
  target_addr,from_addr,ref_type,function_addr,function_name,instruction
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
        print("usage: list_xrefs_to_address.py <addr_hex> [addr_hex...]")
        return 1

    root = Path(__file__).resolve().parents[1]
    targets = [parse_hex(a) for a in sys.argv[1:]]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        listing = program.getListing()

        print("target_addr,from_addr,ref_type,function_addr,function_name,instruction")
        for t in targets:
            taddr = af.getAddress(f"0x{t:08x}")
            refs = rm.getReferencesTo(taddr)
            seen = set()
            for ref in refs:
                from_addr = ref.getFromAddress()
                fn = fm.getFunctionContaining(from_addr)
                fn_name = fn.getName() if fn is not None else "<no_func>"
                fn_addr = str(fn.getEntryPoint()) if fn is not None else "<no_func_addr>"
                ins = listing.getInstructionAt(from_addr)
                ins_text = str(ins) if ins is not None else "<no_inst>"
                rtype = str(ref.getReferenceType())
                key = (str(from_addr), rtype, fn_addr, fn_name, ins_text)
                if key in seen:
                    continue
                seen.add(key)
                print(
                    f"0x{t:08x},{from_addr},{rtype},{fn_addr},{fn_name},\"{ins_text}\""
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
