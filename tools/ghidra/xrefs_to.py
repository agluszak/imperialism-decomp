#!/usr/bin/env python3
"""Read-only: list cross-references for one or more addresses (to / from / both).

TO (default) answers "who calls / stores this address": useful for finding which
constructor writes a given vtable pointer (MI detection: if one ctor writes two
different vtable addresses, the class has a second base), and for caller hunts.
Almost every game function is reached through its incremental-link (ILT) `jmp`
thunk, so a naive xref query on a body address returns exactly one hit: the thunk.
This tool hops through such thunks automatically (one level) and lists the real
callers, so `xrefs 0x581870` answers "who calls this" in one query instead of two.
Address-taken references (a function's address stored in a table or pushed as a
callback) are labeled distinctly from calls — that is how data-registered callbacks
like the movie-done hook hide from call-graph reasoning.

FROM lists what the function containing the address references out — its callees
and data reads — without decompiling it.

usage: xrefs [to|from|both] 0xADDR [0xADDR ...] [--no-thunk-hop] [--limit N]
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env

USAGE = "usage: xrefs [to|from|both] 0xADDR [0xADDR ...] [--no-thunk-hop] [--limit N]"

_DIRECTIONS = ("to", "from", "both")


def parse_query(argv: list[str]) -> tuple[str, list[int], bool, int]:
  """Parse [direction] addrs + flags -> (direction, addrs, thunk_hop, limit).

  Raises ValueError on malformed input (bad flag value, non-hex address).
  """
  direction = "to"
  thunk_hop = True
  limit = 200
  addrs: list[int] = []
  rest = list(argv)
  if rest and rest[0].lower() in _DIRECTIONS:
    direction = rest[0].lower()
    rest = rest[1:]
  it_args = iter(rest)
  for arg in it_args:
    if arg == "--no-thunk-hop":
      thunk_hop = False
    elif arg == "--limit":
      try:
        limit = int(next(it_args))
      except StopIteration:
        raise ValueError("--limit requires a value")
    else:
      addrs.append(int(arg, 16))
  return direction, addrs, thunk_hop, limit


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


def _fmt_fn(fm, addr) -> str:
  fn = fm.getFunctionContaining(addr)
  if fn is None:
    return "?"
  return f"{fn.getName()} ({fn.getEntryPoint()})"


def _print_refs_to(program, target: int, thunk_hop: bool, limit: int) -> None:
  af = program.getAddressFactory().getDefaultAddressSpace()
  rm = program.getReferenceManager()
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


def _print_refs_from(program, target: int, limit: int) -> None:
  """Callees + data reads of the function containing `target` (no decompile needed)."""
  af = program.getAddressFactory().getDefaultAddressSpace()
  fm = program.getFunctionManager()
  rm = program.getReferenceManager()
  listing = program.getListing()
  addr = af.getAddress(target)
  fn = fm.getFunctionContaining(addr)
  if fn is None:
    # No containing function: just the refs originating at this exact address.
    print(f"=== xrefs from {addr} (no containing function) ===")
    refs = rm.getReferencesFrom(addr)
    if not refs:
      print("  (none)")
    for r in refs:
      to = r.getToAddress()
      print(f"  -> {to} [{r.getReferenceType()}] {_fmt_fn(fm, to)}")
    return

  print(f"=== xrefs from {fn.getName()} ({fn.getEntryPoint()}) ===")
  it = listing.getInstructions(fn.getBody(), True)
  n = 0
  while it.hasNext() and n < limit:
    ins = it.next()
    for r in ins.getReferencesFrom():
      if r.getReferenceType().isFlow() and not r.getReferenceType().isCall():
        continue  # skip local fall-through/branch noise; keep calls + data
      to = r.getToAddress()
      if not to.isMemoryAddress():
        continue  # skip stack-slot / register operand refs; keep callees + globals
      print(f"  {ins.getAddress()} -> {to} [{r.getReferenceType()}] {_fmt_fn(fm, to)}")
      n += 1
  if n >= limit:
    print(f"  ...truncated at {limit} (use --limit)")
  if n == 0:
    print("  (none)")


def run(program, argv: list[str]) -> int:
  try:
    direction, addrs, thunk_hop, limit = parse_query(argv)
  except ValueError as exc:
    print(f"{exc}\n{USAGE}", file=sys.stderr)
    return 2
  if not addrs:
    print(USAGE, file=sys.stderr)
    return 2

  for target in addrs:
    if direction in ("to", "both"):
      _print_refs_to(program, target, thunk_hop, limit)
    if direction in ("from", "both"):
      _print_refs_from(program, target, limit)
  return 0


def main() -> int:
  if len(sys.argv) < 2:
    print(USAGE, file=sys.stderr)
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
