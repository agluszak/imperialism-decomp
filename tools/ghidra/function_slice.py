#!/usr/bin/env python3
"""Read-only pyghidra call/offset slice for one or more functions."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pyghidra

PROJECT_LOCATION = os.getenv(
    "GHIDRA_PROJECT_DIR", str(Path(__file__).resolve().parents[2] / "vendor" / "ghidra")
)
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")

MEMORY_REF_RE = re.compile(r"\[(E[A-Z]{2})(?: \+ (0x[0-9a-fA-F]+))?")
VTABLE_CALL_RE = re.compile(r"CALL dword ptr \[(E[A-Z]{2}) \+ (0x[0-9a-fA-F]+)\]")


def parse_addrs(argv: list[str]) -> list[int]:
    return [int(arg, 16) if arg.lower().startswith("0x") else int(arg, 16) for arg in argv]


def function_at_or_containing(program, addr):
    fm = program.getFunctionManager()
    fn = fm.getFunctionContaining(addr)
    if fn is not None:
        return fn
    ins = program.getListing().getInstructionAt(addr)
    if ins is None or ins.getMnemonicString().lower() != "jmp":
        return None
    flows = ins.getFlows()
    if len(flows) != 1:
        return None
    return fm.getFunctionContaining(flows[0])


def fmt_addr(addr) -> str:
    return f"0x{int(str(addr), 16):08x}"


def print_callers(program, fn) -> None:
    fm = program.getFunctionManager()
    refs = []
    for ref in program.getReferenceManager().getReferencesTo(fn.getEntryPoint()):
        caller = fm.getFunctionContaining(ref.getFromAddress())
        caller_name = caller.getName(True) if caller is not None else ""
        refs.append((ref.getFromAddress(), caller_name))
    print("callers:")
    for addr, caller_name in refs[:40]:
        print(f"  {addr},{caller_name}")


def print_body_slice(program, fn) -> None:
    listing = program.getListing()
    fm = program.getFunctionManager()
    callees = []
    indirect_calls = []
    memory_refs = []
    vptr_writes = []

    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        text = str(ins)
        mnemonic = ins.getMnemonicString().upper()
        if mnemonic == "CALL":
            flows = ins.getFlows()
            if len(flows) == 1:
                callee = fm.getFunctionContaining(flows[0])
                callee_name = callee.getName(True) if callee is not None else ""
                callees.append((ins.getAddress(), flows[0], callee_name))
            else:
                match = VTABLE_CALL_RE.search(text)
                if match:
                    indirect_calls.append((ins.getAddress(), match.group(1), match.group(2), text))
                else:
                    indirect_calls.append((ins.getAddress(), "", "", text))

        if mnemonic == "MOV" and "0065" in text and "dword ptr [" in text:
            vptr_writes.append((ins.getAddress(), text))

        for match in MEMORY_REF_RE.finditer(text):
            reg = match.group(1)
            offset = match.group(2) or "0x0"
            memory_refs.append((ins.getAddress(), reg, offset, text))

    print("callees:")
    for addr, target, callee_name in callees:
        print(f"  {addr},{target},{callee_name}")
    print("indirect_calls:")
    for addr, reg, offset, text in indirect_calls:
        print(f"  {addr},{reg},{offset},{text}")
    print("vptr_writes:")
    for addr, text in vptr_writes:
        print(f"  {addr},{text}")
    print("memory_refs:")
    seen = set()
    for addr, reg, offset, text in memory_refs:
        key = (reg, offset, text)
        if key in seen:
            continue
        seen.add(key)
        print(f"  {addr},{reg},{offset},{text}")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: function_slice 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

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
        for addr_int in parse_addrs(sys.argv[1:]):
            addr = af.getAddress(addr_int)
            fn = function_at_or_containing(program, addr)
            print("=" * 72)
            if fn is None:
                print(f"0x{addr_int:08x}: no function")
                continue
            print(
                f"function,{fmt_addr(fn.getEntryPoint())},{fn.getName(True)},"
                f"size={fn.getBody().getNumAddresses()}"
            )
            print_callers(program, fn)
            print_body_slice(program, fn)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
