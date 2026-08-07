#!/usr/bin/env python3
"""Read-only scan: which functions use ECX as `this` (likely __thiscall)?

MSVC __thiscall passes `this` in ECX. A function that reads ECX (as a source
register or a memory base) before ever writing it is almost certainly a thiscall
method, regardless of how its prototype is currently labelled. This flags
__cdecl-labelled functions that are really thiscall (a common Ghidra default
mislabel), and conversely confirms which functions never touch ECX (candidate
true cdecl / static).

Usage: scan_cdecl_thiscall 0xADDR [0xADDR ...]   (addresses to classify)
       scan_cdecl_thiscall --stdin                (read addrs, one per line)
Outholds CSV: address,verdict,first_ecx_use  (verdict = ecx_this | no_ecx | empty)
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env

MAX_INSNS = 10  # how far into the body to look before giving up


def read_addrs() -> list[int]:
  args = sys.argv[1:]
  if args == ["--stdin"]:
    args = [ln.strip() for ln in sys.stdin if ln.strip()]
  return [int(a, 16) for a in args]


def classify(listing, fm, addr):
  fn = fm.getFunctionContaining(addr)
  if fn is None:
    return ("empty", "")
  it = listing.getInstructions(fn.getBody(), True)
  seen = 0
  while it.hasNext() and seen < MAX_INSNS:
    ins = it.next()
    seen += 1
    inputs = {str(o) for o in ins.getInputObjects()}
    results = {str(o) for o in ins.getResultObjects()}
    mn0 = ins.getMnemonicString().lower()
    # `push ecx` at entry is the MSVC "reserve one local" idiom, not a `this` read.
    if mn0 == "push" and "ECX" in str(ins):
      continue
    # ECX read as a source (register or memory base) before any write -> thiscall.
    if any("ECX" in s for s in inputs):
      return ("ecx_this", f"{ins.getAddress()}: {ins}")
    # ECX written first -> not used as incoming `this`.
    if any(s == "ECX" for s in results):
      return ("no_ecx", f"{ins.getAddress()}: {ins}")
    mn = ins.getMnemonicString().lower()
    if mn in ("call", "ret", "retn"):
      return ("no_ecx", f"{ins.getAddress()}: {ins}")
  return ("no_ecx", "")


def main() -> int:
  addrs = read_addrs()
  if not addrs:
    print("usage: scan_cdecl_thiscall 0xADDR ... | --stdin", file=sys.stderr)
    return 2
  project = ghidra_env.open_project()
  consumer = None
  program = None
  try:
    consumer, program = ghidra_env.open_program(project)
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()
    counts = {"ecx_this": 0, "no_ecx": 0, "empty": 0}
    print("address,verdict,first_ecx_use")
    for a in addrs:
      verdict, where = classify(listing, fm, af.getAddress(a))
      counts[verdict] += 1
      print(f"0x{a:08x},{verdict},{where}")
    tot = sum(counts.values())
    print(f"# scanned={tot} ecx_this={counts['ecx_this']} "
          f"no_ecx={counts['no_ecx']} empty={counts['empty']}", file=sys.stderr)
  finally:
    if program is not None:
      program.release(consumer)
    project.close()
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
