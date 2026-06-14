#!/usr/bin/env python3
"""Read-only: slot-ownership matrix across several vtables for a slot range.

For each slot in [lo, hi], resolve every vtable's entry to its real target
(following a single ILT jmp thunk) and print a row, so you can see which
classes override which shared virtual slot.

usage: vtable_matrix lo hi name=0xVT [name=0xVT ...]
  e.g. vtable_matrix 0x73 0x8b Uber=0x65f210 Trade=0x665a70 Prod=0x6653c8
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env


def main() -> int:
  if len(sys.argv) < 4:
    print("usage: vtable_matrix lo hi name=0xVT [...]", file=sys.stderr)
    return 2
  lo = int(sys.argv[1], 16)
  hi = int(sys.argv[2], 16)
  cols = []
  for spec in sys.argv[3:]:
    name, _, addr = spec.partition("=")
    cols.append((name, int(addr, 16)))

  project = ghidra_env.open_project()
  consumer, program = ghidra_env.open_program(project)
  try:
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()

    def resolve(val):
      """Follow a single ILT jmp thunk; return (addr_int, name)."""
      if val == 0:
        return (0, "NULL")
      tgt = af.getAddress(val)
      instr = listing.getInstructionAt(tgt)
      if instr is not None and instr.getMnemonicString().upper() == "JMP":
        fl = instr.getFlows()
        if fl:
          tgt = fl[0]
      fn = fm.getFunctionAt(tgt)
      nm = fn.getName() if fn else f"sub_{tgt}"
      return (int(tgt.getOffset()), nm)

    print("slot " + "".join(f"| {n:<34}" for n, _ in cols))
    for slot in range(lo, hi + 1):
      cells = []
      for _, vt in cols:
        try:
          val = mem.getInt(af.getAddress(vt + slot * 4)) & 0xFFFFFFFF
        except Exception:
          cells.append("<unreadable>"); continue
        _, nm = resolve(val)
        cells.append(nm)
      print(f"{slot:#04x} " + "".join(f"| {c:<34}" for c in cells))
  finally:
    program.release(consumer)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
