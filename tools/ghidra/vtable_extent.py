#!/usr/bin/env python3
"""Read-only: find the real extent of a vtable.

Reads consecutive dwords from a start address, classifying each as a code
pointer (in an executable block / has a function), null, or data. Also reports
any primary symbol sitting at a slot address (which usually marks where one
vtable ends and the next datum/vtable begins).

usage: vtable_extent 0xADDR [max_slots]
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
  if len(sys.argv) < 2:
    print("usage: vtable_extent 0xADDR [max_slots]", file=sys.stderr)
    return 2
  start = int(sys.argv[1], 16)
  max_slots = int(sys.argv[2]) if len(sys.argv) > 2 else 200

  pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
  project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)
  from java.lang import Object as JavaObject

  consumer = JavaObject()
  program_path = PROGRAM_NAME if PROGRAM_NAME.startswith("/") else f"/{PROGRAM_NAME}"
  domain_file = project.getProjectData().getFile(program_path)
  program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())
  try:
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    for i in range(max_slots):
      slot_addr = af.getAddress(start + i * 4)
      try:
        val = mem.getInt(slot_addr) & 0xFFFFFFFF
      except Exception:
        print(f"slot {i:#x} off {i*4:#x}: <unreadable>")
        break
      tgt = af.getAddress(val)
      # classify
      blk = mem.getBlock(tgt) if val else None
      is_exec = bool(blk and blk.isExecute())
      fn = fm.getFunctionContaining(tgt) if val else None
      fn_at = fm.getFunctionAt(tgt) if val else None
      kind = "NULL" if val == 0 else ("CODE" if is_exec else "DATA")
      fname = ""
      if fn_at:
        fname = fn_at.getName()
      elif fn:
        fname = f"in:{fn.getName()}+{tgt.subtract(fn.getEntryPoint()):#x}"
      # primary symbol sitting AT this slot address (marks a boundary)
      sym = st.getPrimarySymbol(slot_addr)
      boundary = ""
      if sym is not None and i > 0:
        boundary = f"  <== SYMBOL@slot: {sym.getName()}"
      # who references this slot address (data refs into the middle = boundary)
      print(f"slot {i:#x} off {i*4:#x} @{slot_addr}: {val:#010x} {kind:4} {fname}{boundary}")
  finally:
    program.release(consumer)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
