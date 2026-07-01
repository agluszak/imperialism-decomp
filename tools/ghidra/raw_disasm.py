#!/usr/bin/env python3
"""Read-only: disassemble raw bytes at an address with capstone, bypassing Ghidra's
instruction/function database entirely.

For when Ghidra hasn't disassembled a region at all (not even as "no function" — no
instruction defined there either). This has come up repeatedly in this binary: Ghidra
sometimes leaves real code completely undefined, with only `int3` alignment padding
visible as the "gap" between two neighboring defined functions once you actually look
at the bytes. `linear_disasm.py` only walks Ghidra's *existing* instruction database
(`Listing.getInstructionAt`), so it correctly reports "no instruction" for such a gap —
that's accurate, not a bug. This tool answers "what's actually in these bytes" instead.

IMPORTANT: reads bytes one at a time via Memory.getByte(Address) — do NOT switch this
to Memory.getBytes(Address, byte[]) with a Python bytearray/bytes buffer. That silently
returns success with the buffer left all-zero in this environment (reproduced under
`python -m` invocation; jpype does not marshal the Java out-param into a Python
buffer). Bit us once already — see docs/TODO.md's "Backdrop window bring-up" section
and search_whole_binary.py's search_dword for the same caveat.

usage: raw_disasm 0xADDR [byte_count]
"""

from __future__ import annotations

import sys

import capstone

from tools.common import ghidra_env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: raw_disasm 0xADDR [byte_count]", file=sys.stderr)
        return 2
    addr_int = int(sys.argv[1], 16)
    nbytes = int(sys.argv[2]) if len(sys.argv) > 2 else 200

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        addr = af.getAddress(addr_int)
        data = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(nbytes))
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    for ins in md.disasm(data, addr_int):
        print(f"0x{ins.address:08x}  {ins.mnemonic} {ins.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
