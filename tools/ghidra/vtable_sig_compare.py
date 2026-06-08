#!/usr/bin/env python3
"""Read-only pyghidra helper: compare several vtables slot-by-slot by *signature*.

For each slot it follows ILT/thunk jumps to the real function and records the
terminating `RET imm16` stack-cleanup byte count (the callee-popped argument
bytes for stdcall/thiscall). Two slots with different cleanup byte counts cannot
be base/override of the same virtual, so this pinpoints where sibling vtables
truly diverge (vs. mere overrides that share a signature).

Usage:
  python -m tools.ghidra.vtable_sig_compare 0x649858:TView 0x64a098:TControl 0x665cc8:TAmtBar --count 200
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pyghidra

PROJECT_LOCATION = os.getenv("GHIDRA_PROJECT_DIR", str(Path(__file__).resolve().parents[2] / "vendor" / "ghidra"))
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")


def parse_int(value: str) -> int:
    raw = value.strip().lower()
    return int(raw, 16) if raw.startswith("0x") else int(raw, 0)


def signed_u32(value: int) -> int:
    return value & 0xFFFFFFFF


def real_function(program, addr):
    """Resolve a vtable entry to its real (non-thunk) function."""
    fm = program.getFunctionManager()
    fn = fm.getFunctionAt(addr)
    if fn is None:
        fn = fm.getFunctionContaining(addr)
    if fn is None:
        return None
    seen = set()
    while fn is not None and fn.isThunk() and fn.getEntryPoint().getOffset() not in seen:
        seen.add(fn.getEntryPoint().getOffset())
        fn = fn.getThunkedFunction(True)
    return fn


def ret_cleanup_bytes(program, fn):
    """Return the callee-popped argument byte count from the terminating RET imm.

    Returns -1 if no RET-with-immediate is found (e.g. RET 0 / plain RET / jmp tail).
    """
    if fn is None:
        return None
    listing = program.getListing()
    cleanup = 0
    found = False
    for ins in listing.getInstructions(fn.getBody(), True):
        mnem = ins.getMnemonicString().upper()
        if mnem in ("RET", "RETN", "RETF"):
            found = True
            if ins.getNumOperands() >= 1:
                scalar = ins.getScalar(0)
                if scalar is not None:
                    cleanup = max(cleanup, int(scalar.getValue()))
    if not found:
        return -1
    return cleanup


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vtables", nargs="+", help="addr:Name entries")
    parser.add_argument("--count", type=parse_int, default=0xC8)
    parser.add_argument("--only-diverge", action="store_true",
                        help="only print rows where cleanup bytes differ across vtables")
    args = parser.parse_args()

    specs = []
    for v in args.vtables:
        addr_s, _, name = v.partition(":")
        specs.append((parse_int(addr_s), name or addr_s))

    pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
    project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)
    from java.lang import Object as JavaObject
    consumer = JavaObject()
    program = None
    try:
        program_path = PROGRAM_NAME if PROGRAM_NAME.startswith("/") else f"/{PROGRAM_NAME}"
        domain_file = project.getProjectData().getFile(program_path)
        program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())
        af = program.getAddressFactory().getDefaultAddressSpace()
        memory = program.getMemory()

        header = ["offset"] + [f"{n}(args)" for _, n in specs] + ["names"]
        print("\t".join(header))
        for index in range(args.count):
            off = index * 4
            cells = []
            names = []
            cleanups = []
            for base_int, _ in specs:
                slot = af.getAddress(base_int + off)
                try:
                    entry_int = signed_u32(memory.getInt(slot))
                except Exception:
                    entry_int = 0
                if entry_int == 0:
                    cells.append("null")
                    cleanups.append(None)
                    names.append("-")
                    continue
                fn = real_function(program, af.getAddress(entry_int))
                cb = ret_cleanup_bytes(program, fn)
                cells.append("null" if cb is None else str(cb))
                cleanups.append(cb)
                names.append(fn.getName() if fn is not None else f"0x{entry_int:08x}")
            real = [c for c in cleanups if c is not None]
            diverge = len(set(real)) > 1
            if args.only_diverge and not diverge:
                continue
            mark = "  <-- SIG DIVERGE" if diverge else ""
            print(f"0x{off:03x}\t" + "\t".join(cells) + "\t" + " | ".join(names) + mark)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
