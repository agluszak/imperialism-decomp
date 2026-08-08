#!/usr/bin/env python3
"""Remove inventory rows whose Ghidra entity is gone, verifying each one first.

`refresh-inventory` never deletes a row. That is deliberate -- absence from an export
does not mean the DB lost the entity (`__seh_longjmp_unwind@4` and the `_$E3xx` EH thunks
live in the DB and appear in no export), and the inventory is also reccmp's original-side
entity list, so a wrong delete silently shrinks what can pair.

But when an entity really is removed -- `just demote-functions`, `just delete-labels`, a
fragment reabsorbed by `just fix-function-bounds` -- its row outlives it, then overlaps
whatever took its bytes and fails `just symbols-integrity-gate`. Hand-editing the CSV was
the only way out (imperialism-decomp-e5ik).

This drops exactly the addresses you name, and only after checking, against the live DB,
that each one has no function and no label, and that no manual-source marker claims it.
Anything that fails a check is reported and kept.

usage:
  inventory-drop 0xADDR [0xADDR ...] [--apply] [--allow-claimed]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

from tools.common.pipe_csv import read_pipe_table
from tools.ghidra.merge_curated_symbols import (
    addr_key,
    collect_source_claimed_addresses,
    write_symbols_csv,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "config" / "original_entities.csv"


@dataclass(frozen=True)
class Verdict:
    address: int
    droppable: bool
    reason: str


def classify(
    address: int,
    rows_by_address: dict[int, dict[str, str]],
    db_addresses: set[int],
    claimed_addresses: set[int],
    *,
    allow_claimed: bool = False,
) -> Verdict:
    """Decide one address without touching anything."""
    if address not in rows_by_address:
        return Verdict(address, False, "no inventory row at this address")
    if address in db_addresses:
        return Verdict(address, False, "the Ghidra DB still has a function or label here")
    if address in claimed_addresses and not allow_claimed:
        return Verdict(
            address, False, "a manual-source marker claims it (pass --allow-claimed to override)"
        )
    return Verdict(address, True, "no DB entity, no source claim")


def db_entity_addresses(program) -> set[int]:
    """Every address the DB has a function or a label at."""
    addresses: set[int] = set()
    for function in program.getFunctionManager().getFunctions(True):
        addresses.add(function.getEntryPoint().getOffset())
    symbol_table = program.getSymbolTable()
    for symbol in symbol_table.getAllSymbols(True):
        addresses.add(symbol.getAddress().getOffset())
    return addresses


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("addresses", nargs="+", help="inventory addresses to drop (0x...)")
    parser.add_argument("--apply", action="store_true",
                        help="rewrite the inventory (default: dry-run)")
    parser.add_argument("--allow-claimed", action="store_true",
                        help="drop even when a source marker claims the address")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    targets = []
    for raw in args.addresses:
        address = addr_key(raw)
        if address is None:
            print(f"not an address: {raw}", file=sys.stderr)
            return 2
        targets.append(address)

    fieldnames, rows = read_pipe_table(INVENTORY)
    rows_by_address: dict[int, dict[str, str]] = {}
    for row in rows:
        address = addr_key(row.get("address") or "")
        if address is not None:
            rows_by_address[address] = row

    from tools.common import ghidra_env

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        db_addresses = db_entity_addresses(program)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    claimed = collect_source_claimed_addresses(REPO_ROOT)
    verdicts = [
        classify(address, rows_by_address, db_addresses, claimed, allow_claimed=args.allow_claimed)
        for address in targets
    ]
    droppable = {verdict.address for verdict in verdicts if verdict.droppable}
    for verdict in verdicts:
        mark = "DROP" if verdict.droppable else "KEEP"
        name = (rows_by_address.get(verdict.address) or {}).get("name", "")
        print(f"[{mark}] 0x{verdict.address:08x} {name} — {verdict.reason}")

    if not droppable:
        print("nothing to drop")
        return 0
    if not args.apply:
        print(f"dry-run; pass --apply to remove {len(droppable)} row(s)")
        return 0

    kept = [row for row in rows if addr_key(row.get("address") or "") not in droppable]
    write_symbols_csv(INVENTORY, fieldnames, kept)
    print(f"removed {len(rows) - len(kept)} row(s) from {INVENTORY.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
