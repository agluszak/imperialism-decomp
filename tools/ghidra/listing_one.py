#!/usr/bin/env python3
"""Read-only pyghidra instruction listing for one or more function addresses."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyghidra

PROJECT_LOCATION = os.getenv("GHIDRA_PROJECT_DIR", str(Path(__file__).resolve().parents[2] / "vendor" / "ghidra"))
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")


def parse_addrs(argv: list[str]) -> list[int]:
  return [int(arg, 16) if arg.lower().startswith("0x") else int(arg, 16) for arg in argv]


def main() -> int:
  if len(sys.argv) < 2:
    print("usage: listing_one 0xADDR [0xADDR ...]", file=sys.stderr)
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
    fm = program.getFunctionManager()
    listing = program.getListing()

    for addr_int in parse_addrs(sys.argv[1:]):
      addr = af.getAddress(addr_int)
      fn = fm.getFunctionContaining(addr)
      print("=" * 72)
      if fn is None:
        # Not inside a defined function: print the single instruction (e.g. an
        # ILT `jmp` thunk) and follow unconditional flow to the final target so
        # vtable-entry thunks can be resolved to their real method bodies.
        ins = listing.getInstructionAt(addr)
        if ins is None:
          print(f"0x{addr_int:08x}: no function, no instruction")
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
  finally:
    if program is not None:
      program.release(consumer)
    project.close()
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
