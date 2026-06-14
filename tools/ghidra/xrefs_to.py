#!/usr/bin/env python3
"""Read-only: list references TO one or more addresses, with the containing function.

Useful for finding which constructor writes a given vtable pointer (MI detection:
if one ctor writes two different vtable addresses, the class has a second base).

usage: xrefs_to 0xADDR [0xADDR ...]
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env


def main() -> int:
  if len(sys.argv) < 2:
    print("usage: xrefs_to 0xADDR [0xADDR ...]", file=sys.stderr)
    return 2
  targets = [int(a, 16) for a in sys.argv[1:]]

  project = ghidra_env.open_project()
  consumer, program = ghidra_env.open_program(project)
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
