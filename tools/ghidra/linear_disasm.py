#!/usr/bin/env python3
"""Read-only: linear disassembly starting at an address, ignoring function boundaries.

Ghidra sometimes mis-bounds large/irregular functions in this binary (confirmed
several times: mega-dispatchers like BuildTurnEventDialogUiByCode/
InitializeGameSetupScreenControlsAndModeTags continue well past the function size
Ghidra reports). `just ghidra-listing` only dumps whichever function *contains* an
address, which is useless once you're past Ghidra's (wrong) end. This walks
instructions strictly by address, independent of function attribution, so you can
follow a tail-jump chain or a mis-bounded function's continuation.

usage: linear_disasm 0xADDR [instruction_count]
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env


def run(program, argv: list[str]) -> int:
    if not argv:
        print("usage: linear-disasm 0xADDR [count]", file=sys.stderr)
        return 2
    addr_int = int(argv[0], 16)
    count = int(argv[1]) if len(argv) > 1 else 60

    af = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    addr = af.getAddress(addr_int)
    cur = listing.getInstructionAt(addr)
    if cur is None:
        print(f"no instruction at 0x{addr_int:08x}")
        return 1
    for _ in range(count):
        if cur is None:
            break
        print(f"{cur.getAddress()}  {cur}")
        cur = listing.getInstructionAt(cur.getAddress().add(cur.getLength()))
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: linear_disasm 0xADDR [count]", file=sys.stderr)
        return 2

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return run(program, sys.argv[1:])
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    sys.exit(main())
