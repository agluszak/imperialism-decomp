#!/usr/bin/env python3
"""Read-only: resolve vtable_dump.py CSV entry_addr thunks to their real body address
+ owning function name (follows JMP chains, does not write to the Ghidra DB).

Usage:
  uv run python -m tools.ghidra.resolve_vtable_slots /tmp/vt/TFoo.csv [...]
"""
from __future__ import annotations

import csv
import sys

from tools.common import ghidra_env


def resolve(listing, af, addr_int: int):
    cur = af.getAddress(addr_int)
    for _ in range(8):
        ins = listing.getInstructionAt(cur)
        if ins is None:
            break
        flows = ins.getFlows()
        if ins.getMnemonicString() == "JMP" and len(flows) == 1:
            cur = flows[0]
            continue
        break
    return cur


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        print("usage: resolve_vtable_slots.py <csv> [...]", file=sys.stderr)
        return 2

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        writer = csv.writer(sys.stdout)
        writer.writerow(
            ["class_name", "index", "byte_offset", "raw_entry_addr", "resolved_addr", "resolved_name"]
        )
        for path in paths:
            with open(path, newline="") as fh:
                for row in csv.DictReader(fh):
                    entry = row.get("entry_addr", "")
                    if not entry:
                        continue
                    entry_int = int(entry, 16)
                    if entry_int == 0:
                        writer.writerow([row["class_name"], row["index"], row["byte_offset"], entry, "0x00000000", ""])
                        continue
                    resolved = resolve(listing, af, entry_int)
                    fn = fm.getFunctionContaining(resolved)
                    name = fn.getName(True) if fn is not None else ""
                    writer.writerow(
                        [
                            row["class_name"],
                            row["index"],
                            row["byte_offset"],
                            entry,
                            f"0x{resolved.getOffset():08x}",
                            name,
                        ]
                    )
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
