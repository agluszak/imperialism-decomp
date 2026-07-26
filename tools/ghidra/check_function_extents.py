#!/usr/bin/env python3
"""Read-only: find curated functions whose recorded extent stops mid-body.

A function's byte range should end on a terminator -- ret, an unconditional jmp (tail
call), or int3 padding. When Ghidra's bounds are short the range ends on something like
`push 0x198`, which is the middle of an assert call. Two of those have already cost real
work:

  0x50e8b0 TMapMgr::AllocateAndResetTerrainAndCityScoreTables -- recorded 81 bytes,
    actually 747. reccmp compared the function through an 81-byte keyhole; repairing the
    size took it 18.99% -> 27.30%.
  0x4cb8a0 TUniversityView::DoEvent -- recorded 301 bytes, actually 506. The missing tail
    contains the ILT-thunked call to TControl::DoEvent, so a byte scan of the recorded
    range "proved" a base delegation was invented when it is right there in the original.
    That false positive is what made the imperialism-decomp-4km.17 audit unsound and led
    to seven correct base calls being deleted and restored.

So a truncated extent corrupts two things at once: the reccmp score, and any analysis
that scans a function's bytes. This finds them mechanically instead of by accident.

The check walks Ghidra's instruction listing from the entry to the recorded end and looks
at the final instruction inside the range. Anything that is not a terminator is reported,
together with the next few instructions past the boundary so the real end is visible.
Reports only; repairing a row is a curation decision (edit the size in
config/original_entities.csv, rebuild, and confirm the score moves).

usage: check-function-extents [limit]
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

TERMINATORS = {"RET", "RETF", "JMP", "INT3", "UD2"}
REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "config" / "original_entities.csv"


def owned_functions() -> list[tuple[int, int, str]]:
    """(address, size, name) for every curated row that is a sized function."""
    rows = []
    with INVENTORY.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="|"):
            if (row.get("type") or "").strip() != "function":
                continue
            size = (row.get("size") or "").strip()
            address = (row.get("address") or "").strip()
            if not size.isdigit() or not address:
                continue
            if int(size) < 8:
                # Degenerate 1-byte rows are a different defect with its own repair
                # target (just fix-function-bounds); skip them here.
                continue
            rows.append((int(address, 16), int(size), (row.get("name") or "").strip()))
    return rows


def run(program, argv: list[str]) -> int:
    limit = int(argv[0]) if argv else 0
    listing = program.getListing()
    space = program.getAddressFactory().getDefaultAddressSpace()

    findings = []
    for address, size, name in owned_functions():
        end = address + size
        start_addr = space.getAddress(address)
        if listing.getInstructionAt(start_addr) is None:
            continue  # not disassembled; not this check's business

        last = None
        cursor = listing.getInstructionAt(start_addr)
        while cursor is not None:
            insn_start = cursor.getAddress().getOffset()
            if insn_start >= end:
                break
            last = cursor
            cursor = cursor.getNext()

        if last is None:
            continue
        mnemonic = str(last.getMnemonicString()).upper()
        if mnemonic in TERMINATORS:
            continue
        # A conditional jump backwards into the body is a loop tail, which is a legitimate
        # (if unusual) last instruction only when the next byte starts another function.
        following = listing.getInstructionAt(space.getAddress(end))
        findings.append(
            (
                address,
                size,
                name,
                last.getAddress().getOffset(),
                f"{mnemonic} {last.getDefaultOperandRepresentation(0) if last.getNumOperands() else ''}".strip(),
                str(following) if following is not None else "(no instruction at boundary)",
            )
        )

    findings.sort(key=lambda item: -item[1])
    print(f"curated sized functions checked: {len(owned_functions())}")
    print(f"extents ending on a non-terminator: {len(findings)}\n")
    for address, size, name, last_at, text, following in findings[: limit or len(findings)]:
        print(f"0x{address:08x} {name}")
        print(f"    recorded size {size} (ends 0x{address + size:08x})")
        print(f"    last insn in range  0x{last_at:08x}  {text}")
        print(f"    at boundary         {following}")
    return 0


def main() -> int:
    from tools.common import ghidra_env

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
    sys.exit(main())
