#!/usr/bin/env python3
"""Resolve vtable slots through ILT thunks to real bodies and report port status.

usage: vtable_port_queue.py 0xVTABLE_ADDR SLOT_COUNT owned_addrs.txt
owned_addrs.txt: one 0x-hex address per line (already-owned FUNCTION markers).
Prints CSV: slot,byte_off,thunk,target,name,size,owned
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyghidra

PROJECT_LOCATION = os.getenv("GHIDRA_PROJECT_DIR", str(Path(__file__).resolve().parents[2] / "vendor" / "ghidra"))
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")


def main() -> int:
  vtable = int(sys.argv[1], 16)
  count = int(sys.argv[2], 0)
  owned = set()
  if len(sys.argv) > 3:
    owned = {int(line.strip(), 16) for line in Path(sys.argv[3]).read_text().splitlines() if line.strip()}

  pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
  project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)

  from java.lang import Object as JavaObject

  consumer = JavaObject()
  program = None
  try:
    domain_file = project.getProjectData().getFile(f"/{PROGRAM_NAME}")
    program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()
    mem = program.getMemory()

    print("slot,byte_off,thunk,target,name,size,owned")
    for i in range(count):
      slot_addr = af.getAddress(vtable + 4 * i)
      try:
        entry = mem.getInt(slot_addr) & 0xFFFFFFFF
      except Exception:
        print(f"0x{i:02x},0x{4*i:03x},READ_FAIL,,,,")
        continue
      target = entry
      # follow jmp chains
      for _ in range(8):
        fn = fm.getFunctionContaining(af.getAddress(target))
        if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
          break
        ins = listing.getInstructionAt(af.getAddress(target))
        if ins is None:
          break
        if ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
          target = int(ins.getFlows()[0].getOffset())
        else:
          break
      fn = fm.getFunctionContaining(af.getAddress(target))
      name = fn.getName() if fn is not None else "?"
      size = fn.getBody().getNumAddresses() if fn is not None else 0
      print(f"0x{i:02x},0x{4*i:03x},0x{entry:08x},0x{target:08x},{name},{size},{1 if target in owned else 0}")
  finally:
    if program is not None:
      program.release(consumer)
    project.close()
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
