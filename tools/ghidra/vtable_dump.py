#!/usr/bin/env python3
"""Read-only pyghidra vtable dump helper.

Emits vtable entries as CSV using explicit index and byte-offset columns.
"""

from __future__ import annotations

import argparse
import csv
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dump a Windows/MSVC vtable from a Ghidra project.")
    parser.add_argument("class_name")
    parser.add_argument("vtable_addr")
    parser.add_argument("--count", type=lambda value: parse_int(value), default=0xB8)
    return parser.parse_args()


def signed_u32(value: int) -> int:
    return value & 0xFFFFFFFF


def symbol_name(program, addr) -> str:
    symbol = program.getSymbolTable().getPrimarySymbol(addr)
    return symbol.getName(True) if symbol is not None else ""


def function_name(program, addr) -> str:
    fn = program.getFunctionManager().getFunctionContaining(addr)
    if fn is None:
        return symbol_name(program, addr)
    return fn.getName(True)


def xref_summary(program, addr, limit: int = 8) -> str:
    refs = []
    for ref in program.getReferenceManager().getReferencesTo(addr):
        refs.append(str(ref.getFromAddress()))
        if len(refs) >= limit:
            break
    return ";".join(refs)


def main() -> int:
    args = parse_args()

    pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
    project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)

    from java.lang import Object as JavaObject

    consumer = JavaObject()
    program = None
    try:
        program_path = PROGRAM_NAME if PROGRAM_NAME.startswith("/") else f"/{PROGRAM_NAME}"
        domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            raise FileNotFoundError(f'Program "{PROGRAM_NAME}" not found in project.')
        program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())

        af = program.getAddressFactory().getDefaultAddressSpace()
        memory = program.getMemory()
        base = af.getAddress(args.vtable_addr)

        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=[
                "class_name",
                "vtable_addr",
                "index",
                "byte_offset",
                "entry_addr",
                "current_name",
                "return_type",
                "args",
                "evidence_status",
                "evidence",
                "entry_xrefs",
                "slot_xrefs",
            ],
        )
        writer.writeheader()
        for index in range(args.count):
            slot_addr = base.add(index * 4)
            try:
                entry_int = signed_u32(memory.getInt(slot_addr))
            except Exception:
                break
            entry_addr = af.getAddress(entry_int)
            current = function_name(program, entry_addr)
            writer.writerow(
                {
                    "class_name": args.class_name,
                    "vtable_addr": f"0x{parse_int(args.vtable_addr):08x}",
                    "index": f"0x{index:02x}",
                    "byte_offset": f"0x{index * 4:03x}",
                    "entry_addr": f"0x{entry_int:08x}",
                    "current_name": current,
                    "return_type": "",
                    "args": "",
                    "evidence_status": "raw",
                    "evidence": f"read pointer at 0x{parse_int(args.vtable_addr) + index * 4:08x}",
                    "entry_xrefs": xref_summary(program, entry_addr),
                    "slot_xrefs": xref_summary(program, slot_addr),
                }
            )
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
