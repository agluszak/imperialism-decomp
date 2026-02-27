#!/usr/bin/env python3
"""
List callsites/callers for one or more function addresses.

Usage:
  .venv/bin/python new_scripts/list_function_callers.py <addr_hex> [addr_hex...]

Output columns:
  target_addr,target_name,call_from,caller_addr,caller_name,instruction
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
        print("usage: list_function_callers.py <addr_hex> [addr_hex...]")
        return 1

    root = Path(__file__).resolve().parents[1]
    targets = [parse_hex(a) for a in sys.argv[1:]]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()

        print("target_addr,target_name,call_from,caller_addr,caller_name,instruction")
        for target_int in targets:
            target_addr = af.getAddress(f"0x{target_int:08x}")
            target_fn = fm.getFunctionAt(target_addr)
            target_name = target_fn.getName() if target_fn is not None else "<no_func>"

            seen = set()
            refs = rm.getReferencesTo(target_addr)
            for ref in refs:
                from_addr = ref.getFromAddress()
                caller_fn = fm.getFunctionContaining(from_addr)
                caller_name = caller_fn.getName() if caller_fn is not None else "<no_func>"
                caller_ep = (
                    str(caller_fn.getEntryPoint()) if caller_fn is not None else "<no_func_addr>"
                )
                ins = listing.getInstructionAt(from_addr)
                ins_text = str(ins) if ins is not None else "<no_inst>"
                key = (str(from_addr), caller_ep, caller_name, ins_text)
                if key in seen:
                    continue
                seen.add(key)
                print(
                    f"0x{target_int:08x},{target_name},{from_addr},{caller_ep},{caller_name},\"{ins_text}\""
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
