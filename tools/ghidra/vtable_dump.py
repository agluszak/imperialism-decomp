#!/usr/bin/env python3
"""Read-only pyghidra vtable dump helper.

Emits vtable entries as CSV using explicit index and byte-offset columns.
"""

from __future__ import annotations

import argparse
import csv
import sys

from tools.common import ghidra_env


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


def run(program, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="vtable-dump",
                                     description="Dump a Windows/MSVC vtable from a Ghidra project.")
    parser.add_argument("class_name")
    parser.add_argument("vtable_addr")
    parser.add_argument("--count", type=lambda value: parse_int(value), default=0xB8)
    args = parser.parse_args(argv)
    return _dump(program, args)


def main() -> int:
    args = parse_args()

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return _dump(program, args)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


def _dump(program, args: argparse.Namespace) -> int:
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
