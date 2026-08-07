#!/usr/bin/env python3
"""Delete stale user labels from the Ghidra DB (and thus from the next inventory export).

A label at an address that manual source has since subsumed into a typed struct
region (e.g. `g_NetworkDefaultNationId006a5fc0` at g_NetworkSessionManager+0x60)
poisons reccmp's original-side operand rendering: the exact-address label wins
over the correct base+offset form and every referencing function drops. Deleting
the CSV row alone is not enough — `just refresh-inventory` re-exports the label
from the DB — so remove the DB symbol itself.

Refuses to touch an address that is a function entry (use demote_functions for
those) and reports when nothing is there. Dry-run by default.

usage:
  delete_labels 0xADDR [0xADDR ...] [--apply]
"""

from __future__ import annotations

import argparse

from tools.common import ghidra_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", nargs="+", help="Label addresses (0x...).")
    parser.add_argument("--apply", action="store_true",
                        help="Delete and save the program (default: dry-run).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    import pyghidra

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project, writable=args.apply)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        symtab = program.getSymbolTable()

        plan = []
        for text in args.addresses:
            addr = int(text, 16)
            gaddr = af.getAddress(addr)
            if fm.getFunctionAt(gaddr) is not None:
                print(f"0x{addr:08x}: is a FUNCTION entry — use demote_functions instead")
                continue
            syms = list(symtab.getSymbols(gaddr))
            if not syms:
                print(f"0x{addr:08x}: no symbols (nothing to delete)")
                continue
            for s in syms:
                plan.append((addr, s))
                print(f"0x{addr:08x}: would delete label {s.getName()} ({s.getSource()})")

        if not args.apply:
            print("dry-run; pass --apply to delete + save")
            return 0
        if not plan:
            return 0

        txid = program.startTransaction("delete stale labels")
        try:
            for addr, s in plan:
                s.delete()
        finally:
            program.endTransaction(txid, True)
        program.getDomainFile().save(pyghidra.task_monitor())
        print(f"deleted {len(plan)} label(s); saved program — re-run `just refresh-inventory` "
              f"and `just export-project`")
        return 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
