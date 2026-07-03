#!/usr/bin/env python3
"""Read-only pyghidra instruction listing for one or more function addresses."""

from __future__ import annotations

import sys

from tools.common import ghidra_env


def parse_addrs(argv: list[str]) -> list[int]:
  return [int(arg, 16) if arg.lower().startswith("0x") else int(arg, 16) for arg in argv]


def _print_nearest_functions(fm, af, addr_int: int) -> None:
  """Orient the caller when an address hits a Ghidra gap (no function, no instruction)."""
  addr = af.getAddress(addr_int)
  before_it = fm.getFunctions(addr, False)
  after_it = fm.getFunctions(addr, True)
  before = before_it.next() if before_it.hasNext() else None
  after = after_it.next() if after_it.hasNext() else None
  if before is not None:
    end = before.getBody().getMaxAddress()
    print(f"  nearest function before: {before.getName()} entry={before.getEntryPoint()} end={end}")
  if after is not None:
    print(f"  nearest function after:  {after.getName()} entry={after.getEntryPoint()}")
  print(f"  hint: `just ghidra-raw-disasm 0x{addr_int:08x}` shows what is really in the gap")


def run(program, argv: list[str]) -> int:
  """Print listings for the given addresses; `program` stays open (caller owns it)."""
  if not argv:
    print("usage: listing 0xADDR [0xADDR ...]", file=sys.stderr)
    return 2

  af = program.getAddressFactory().getDefaultAddressSpace()
  fm = program.getFunctionManager()
  listing = program.getListing()

  for addr_int in parse_addrs(argv):
    addr = af.getAddress(addr_int)
    fn = fm.getFunctionContaining(addr)
    print("=" * 72)
    if fn is None:
      # Not inside a defined function: print the single instruction (e.g. an
      # ILT `jmp` thunk) and follow unconditional flow to the final target so
      # vtable-entry thunks can be resolved to their real method bodies.
      ins = listing.getInstructionAt(addr)
      if ins is None:
        print(f"0x{addr_int:08x}: no function, no instruction (Ghidra gap)")
        _print_nearest_functions(fm, af, addr_int)
        continue
      print(f"0x{addr_int:08x}  (no function) {ins}")
      cur = ins
      for _ in range(8):
        flows = cur.getFlows()
        mnem = cur.getMnemonicString().lower()
        if mnem != "jmp" or len(flows) != 1:
          break
        tgt = flows[0]
        tfn = fm.getFunctionContaining(tgt)
        if tfn is not None:
          print(f"  -> {tgt}  {tfn.getName()}  entry={tfn.getEntryPoint()} size={tfn.getBody().getNumAddresses()}")
          break
        nxt = listing.getInstructionAt(tgt)
        if nxt is None:
          print(f"  -> {tgt}  (no function, no instruction)")
          break
        print(f"  -> {tgt}  {nxt}")
        cur = nxt
      continue
    print(f"0x{addr_int:08x}  {fn.getName()}  entry={fn.getEntryPoint()} size={fn.getBody().getNumAddresses()}")
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
      ins = it.next()
      print(f"{ins.getAddress()}  {ins}")
  return 0


def main() -> int:
  if len(sys.argv) < 2:
    print("usage: listing_one 0xADDR [0xADDR ...]", file=sys.stderr)
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
  raise SystemExit(main())
