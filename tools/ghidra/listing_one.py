#!/usr/bin/env python3
"""Read-only pyghidra instruction listing for one or more function addresses."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyghidra

PROJECT_LOCATION = os.getenv("GHIDRA_PROJECT_DIR", "/home/agluszak/code/decomp/imperialism_knowledge")
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
        print(f"0x{addr_int:08x}: no function")
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
