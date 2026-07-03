#!/usr/bin/env python3
"""Read-only: list references TO one or more addresses, with the containing function.

Useful for finding which constructor writes a given vtable pointer (MI detection:
if one ctor writes two different vtable addresses, the class has a second base),
and for caller hunts.

Almost every game function is reached through its incremental-link (ILT) `jmp`
thunk, so a naive xref query on a body address returns exactly one hit: the thunk.
This tool hops through such thunks automatically (one level) and lists the real
callers, so `xrefs 0x581870` answers "who calls this" in one query instead of two.
Address-taken references (a function's address stored in a table or pushed as a
callback) are labeled distinctly from calls — that is how data-registered callbacks
like the movie-done hook hide from call-graph reasoning.

usage: xrefs_to 0xADDR [0xADDR ...] [--no-thunk-hop] [--limit N]
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env


def _is_jump_thunk(program, from_addr) -> bool:
  """True when `from_addr` is a lone unconditional `jmp` (typical ILT thunk site)."""
  listing = program.getListing()
  ins = listing.getInstructionAt(from_addr)
  if ins is None:
    return False
  if ins.getMnemonicString().lower() != "jmp":
    return False
  fn = program.getFunctionManager().getFunctionContaining(from_addr)
  # ILT thunks are usually not functions at all (pruned rows) or Ghidra thunk fns.
  return fn is None or bool(fn.isThunk())


def _describe_from(program, ref) -> str:
  fm = program.getFunctionManager()
  frm = ref.getFromAddress()
  fn = fm.getFunctionContaining(frm)
  fname = fn.getName() if fn else "?"
  fentry = fn.getEntryPoint() if fn else "?"
  ref_type = ref.getReferenceType()
  kind = str(ref_type)
  if ref_type.isData():
    kind = f"{kind} address-taken/data"
  return f"from {frm} [{kind}] in {fname} ({fentry})"


def run(program, argv: list[str]) -> int:
  thunk_hop = True
  limit = 200
  addrs: list[int] = []
  it_args = iter(argv)
  for arg in it_args:
    if arg == "--no-thunk-hop":
      thunk_hop = False
    elif arg == "--limit":
      try:
        limit = int(next(it_args))
      except StopIteration:
        print("--limit requires a value", file=sys.stderr)
        return 2
    else:
      addrs.append(int(arg, 16))
  if not addrs:
    print("usage: xrefs 0xADDR [0xADDR ...] [--no-thunk-hop] [--limit N]", file=sys.stderr)
    return 2

  af = program.getAddressFactory().getDefaultAddressSpace()
  rm = program.getReferenceManager()

  for target in addrs:
    addr = af.getAddress(target)
    print(f"=== xrefs to {addr} ===")
    n = 0
    refs = rm.getReferencesTo(addr)
    while refs.hasNext() and n < limit:
      r = refs.next()
      frm = r.getFromAddress()
      if thunk_hop and _is_jump_thunk(program, frm):
        print(f"  via thunk {frm} [{r.getReferenceType()}]:")
        inner = rm.getReferencesTo(frm)
        hops = 0
        while inner.hasNext() and n < limit:
          r2 = inner.next()
          print(f"    {_describe_from(program, r2)}")
          n += 1
          hops += 1
        if hops == 0:
          print("    (thunk itself has no references)")
        continue
      print(f"  {_describe_from(program, r)}")
      n += 1
    if n >= limit:
      print(f"  ...truncated at {limit} (use --limit)")
    if n == 0:
      print("  (none)")
  return 0


def main() -> int:
  if len(sys.argv) < 2:
    print("usage: xrefs_to 0xADDR [0xADDR ...] [--no-thunk-hop] [--limit N]", file=sys.stderr)
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
