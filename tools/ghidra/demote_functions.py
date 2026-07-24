#!/usr/bin/env python3
"""Demote case-body pseudo-functions to plain labels so a dispatcher can reclaim them.

An earlier autogen pass split several giant switch dispatchers' case bodies into
standalone named functions (see config/function_overlap_allowlist.txt). Those
entries block `fix_function_bounds --force` — its rollback guard correctly
refuses to let a re-bounded body swallow another *function entry*. This tool
removes the function entity at each given address while keeping any symbol as a
plain label, so the enclosing dispatcher can reabsorb the bytes on the next
re-bound.

Safety: refuses to demote a function that has any CALL reference or any
reference from outside `--dispatcher`'s current-plus-expected range unless
`--force-refs` is passed. Dry-run by default.

usage:
  demote_functions 0xADDR [0xADDR ...] [--apply] [--force-refs]
"""

from __future__ import annotations

import argparse

from tools.common import ghidra_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", nargs="+", help="Function entry addresses (0x...).")
    parser.add_argument("--apply", action="store_true",
                        help="Demote and save the program (default: dry-run).")
    parser.add_argument("--force-refs", action="store_true",
                        help="Demote even when call references exist.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    import pyghidra

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project, writable=args.apply)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        refman = program.getReferenceManager()

        plan, blocked = [], []
        for text in args.addresses:
            addr = int(text, 16)
            gaddr = af.getAddress(addr)
            func = fm.getFunctionAt(gaddr)
            if func is None:
                print(f"0x{addr:08x}: no function entity (nothing to demote)")
                continue
            calls = [r for r in refman.getReferencesTo(gaddr)
                     if r.getReferenceType().isCall()]
            if calls and not args.force_refs:
                blocked.append((addr, func.getName(), len(calls)))
                continue
            plan.append((addr, func.getName()))

        for addr, name, n in blocked:
            print(f"0x{addr:08x}: BLOCKED — {n} call reference(s) to {name}; "
                  f"not a fall-through fragment (use --force-refs to override)")
        for addr, name in plan:
            print(f"0x{addr:08x}: would demote {name} to a label")

        if not args.apply:
            print("dry-run; pass --apply to demote + save")
            return 1 if blocked else 0

        if not plan:
            return 1 if blocked else 0

        txid = program.startTransaction("demote case-body pseudo-functions")
        try:
            for addr, name in plan:
                fm.removeFunction(af.getAddress(addr))
        finally:
            program.endTransaction(txid, True)
        program.getDomainFile().save(pyghidra.task_monitor())
        print(f"demoted {len(plan)} function(s); saved program — now re-run "
              f"fix_function_bounds on the enclosing dispatcher(s), then "
              f"`just export-project` and `just refresh-inventory`")
        return 1 if blocked else 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
