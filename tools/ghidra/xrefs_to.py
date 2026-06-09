#!/usr/bin/env python3
"""Read-only: list references TO one or more addresses, with the containing function.

Useful for finding which constructor writes a given vtable pointer (MI detection:
if one ctor writes two different vtable addresses, the class has a second base).

usage: xrefs_to 0xADDR [0xADDR ...]
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
    print("usage: xrefs_to 0xADDR [0xADDR ...]", file=sys.stderr)
    return 2
  targets = [int(a, 16) for a in sys.argv[1:]]

  pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
  project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)
  from java.lang import Object as JavaObject

  consumer = JavaObject()
  program_path = PROGRAM_NAME if PROGRAM_NAME.startswith("/") else f"/{PROGRAM_NAME}"
  domain_file = project.getProjectData().getFile(program_path)
  program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())
  try:
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    for t in targets:
      addr = af.getAddress(t)
      print(f"=== xrefs to {addr} ===")
      it = rm.getReferencesTo(addr)
      n = 0
      while it.hasNext():
        r = it.next()
        frm = r.getFromAddress()
        fn = fm.getFunctionContaining(frm)
        fname = fn.getName() if fn else "?"
        fentry = fn.getEntryPoint() if fn else "?"
        print(f"  from {frm} [{r.getReferenceType()}] in {fname} ({fentry})")
        n += 1
      if n == 0:
        print("  (none)")
  finally:
    program.release(consumer)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
