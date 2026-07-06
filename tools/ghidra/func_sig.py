#!/usr/bin/env python3
"""Read-only signature facts for one or more functions, as a pipe table.

For each address prints: address|name|cc|params|ret_imm|size

  cc / params — Ghidra's calling convention and parameter count. These are
    HYPOTHESES (Ghidra default-labels unknowns __cdecl and mislabels ~33% of
    them); use them as leads, never ground truth.
  ret_imm — stack bytes purged by `RET imm16`, or 0 for a plain RET. This IS
    ground truth from the binary: a callee-cleaned (__stdcall/__thiscall)
    function purges exactly 4 bytes per stack dword of its arguments.
  size — body size in bytes.

usage: func-sig 0xADDR [0xADDR ...]
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env

HEADER = "address|name|cc|params|ret_imm|size"


def ret_imm_bytes(program, fn) -> int:
    """Largest RET immediate in the body (0 for plain RET / no RET found)."""
    listing = program.getListing()
    best = 0
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        if not ins.getMnemonicString().upper().startswith("RET"):
            continue
        for i in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(i):
                try:
                    best = max(best, int(obj.getValue()))
                except AttributeError:
                    continue
    return best


def run(program, argv: list[str]) -> int:
    addrs = [a for a in argv if not a.startswith("-")]
    if not addrs:
        print("usage: func-sig 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    print(HEADER)
    for arg in addrs:
        addr_int = int(arg, 16)
        fn = fm.getFunctionContaining(af.getAddress(addr_int))
        if fn is None:
            print(f"0x{addr_int:08x}|<no function>||||")
            continue
        entry = int(str(fn.getEntryPoint()), 16)
        print(
            f"0x{entry:08x}|{fn.getName(True)}|{fn.getCallingConventionName()}|"
            f"{fn.getParameterCount()}|{ret_imm_bytes(program, fn)}|"
            f"{fn.getBody().getNumAddresses()}"
        )
    return 0


def main() -> int:
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
    raise SystemExit(main())
