#!/usr/bin/env python3
"""Read-only cross-reference dump for one or more addresses.

Lists, for each target address:
  * refs TO   -- who references the address (call sites, data reads, vtable slot reads),
                 with the containing function name/entry.
  * refs FROM -- what the address (or the function containing it) references out, so you can
                 see a function's callees / data reads without decompiling.

usage:
  xrefs [to|from|both] 0xADDR [0xADDR ...]

The leading direction keyword is optional and defaults to `both`.
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env

_DIRECTIONS = {"to", "from", "both"}


def _fmt_fn(fm, addr) -> str:
    fn = fm.getFunctionContaining(addr)
    if fn is None:
        return "?"
    return f"{fn.getName()} ({fn.getEntryPoint()})"


def _print_refs_to(program, addr_int: int) -> None:
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    addr = af.getAddress(addr_int)
    print(f"=== xrefs TO 0x{addr_int:08x} ({addr}) ===")
    it = rm.getReferencesTo(addr)
    n = 0
    while it.hasNext():
        r = it.next()
        frm = r.getFromAddress()
        print(f"  from {frm} [{r.getReferenceType()}] in {_fmt_fn(fm, frm)}")
        n += 1
    if n == 0:
        print("  (none)")


def _print_refs_from(program, addr_int: int) -> None:
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    listing = program.getListing()
    addr = af.getAddress(addr_int)
    fn = fm.getFunctionContaining(addr)
    if fn is None:
        # No containing function: just the refs originating at this exact address.
        print(f"=== xrefs FROM 0x{addr_int:08x} ({addr}) ===")
        refs = rm.getReferencesFrom(addr)
        if not refs:
            print("  (none)")
        for r in refs:
            to = r.getToAddress()
            print(f"  -> {to} [{r.getReferenceType()}] {_fmt_fn(fm, to)}")
        return

    print(f"=== xrefs FROM {fn.getName()} ({fn.getEntryPoint()}) — 0x{addr_int:08x} ===")
    body = fn.getBody()
    it = listing.getInstructions(body, True)
    seen = 0
    while it.hasNext():
        ins = it.next()
        for r in ins.getReferencesFrom():
            if r.getReferenceType().isFlow() and not r.getReferenceType().isCall():
                continue  # skip local fall-through/branch noise; keep calls + data
            to = r.getToAddress()
            print(f"  {ins.getAddress()} -> {to} [{r.getReferenceType()}] {_fmt_fn(fm, to)}")
            seen += 1
    if seen == 0:
        print("  (none)")


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: xrefs [to|from|both] 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

    direction = "both"
    if argv[0].lower() in _DIRECTIONS:
        direction = argv[0].lower()
        argv = argv[1:]
    if not argv:
        print("usage: xrefs [to|from|both] 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

    targets = [int(a, 16) for a in argv]

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        for t in targets:
            if direction in ("to", "both"):
                _print_refs_to(program, t)
            if direction in ("from", "both"):
                _print_refs_from(program, t)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
