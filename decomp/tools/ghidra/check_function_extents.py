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

An extent can also be too LARGE, which corrupts the same two things. The oversize pass
reports a recorded range that swallows the entry of the next curated function row: the
compare window then spans two functions, so the score mixes in bytes the source never
claimed and a byte scan "finds" callees belonging to the neighbour. Repairing a
truncated row is usually a score win; repairing an oversized one is a truth fix that can
lower a falsely-inflated number, so both are reported and neither is applied here.

Sizing rule for switch functions: the extent runs to the end of the trailing jump/index
tables, not to the last `ret`. Code-only sizing left CDib::ComputePaletteSize at 51.69%;
including its tables took the same source to 100%.

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


def oversize_findings(rows: list[tuple[int, int, str]]) -> list[tuple[int, int, str, int, str, int]]:
    """Rows whose recorded range swallows the entry of the next curated function.

    Overlap is decided against curated rows alone, so it holds regardless of what
    Ghidra believes about either body.  Padding between two functions is not an
    overlap: only a recorded end strictly past the next entry counts.
    """
    ordered = sorted(rows)
    findings = []
    for index, (address, size, name) in enumerate(ordered):
        if index + 1 >= len(ordered):
            continue
        next_address, _next_size, next_name = ordered[index + 1]
        end = address + size
        if end <= next_address:
            continue
        findings.append(
            (address, size, name, next_address, next_name, end - next_address)
        )
    return findings


def interior_padding_findings(
    program, rows: list[tuple[int, int, str]], min_run: int = 4
) -> list[tuple[int, int, str, int, int]]:
    """Rows whose recorded range spans an int3 alignment run with code after it.

    Inter-function alignment padding inside a recorded extent means the range covers
    more than one function, which the next-row overlap test misses whenever the
    swallowed function has no curated row of its own.  Trailing padding at the very
    end of the range is normal and is not reported.
    """
    listing = program.getListing()
    space = program.getAddressFactory().getDefaultAddressSpace()
    findings = []
    for address, size, name in rows:
        end = address + size
        cursor = listing.getInstructionAt(space.getAddress(address))
        run_start = None
        run_length = 0
        spill = None
        while cursor is not None:
            offset = cursor.getAddress().getOffset()
            if offset >= end:
                break
            if str(cursor.getMnemonicString()).upper() == "INT3":
                if run_start is None:
                    run_start = offset
                run_length += cursor.getLength()
            else:
                if run_start is not None and run_length >= min_run:
                    spill = run_start
                    break
                run_start = None
                run_length = 0
            cursor = cursor.getNext()
        if spill is not None:
            findings.append((address, size, name, spill, end - spill))
    return findings


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
    rows = owned_functions()
    oversize = oversize_findings(rows)
    padded = interior_padding_findings(program, rows)
    print(f"curated sized functions checked: {len(rows)}")
    print(f"extents ending on a non-terminator: {len(findings)}")
    print(f"extents overlapping the next function: {len(oversize)}")
    print(f"extents spanning interior alignment padding: {len(padded)}\n")
    for address, size, name, last_at, text, following in findings[: limit or len(findings)]:
        print(f"0x{address:08x} {name}")
        print(f"    recorded size {size} (ends 0x{address + size:08x})")
        print(f"    last insn in range  0x{last_at:08x}  {text}")
        print(f"    at boundary         {following}")
    if oversize:
        print("\n-- oversized extents (recorded range swallows the next function) --")
        oversize.sort(key=lambda item: -item[5])
        for address, size, name, next_address, next_name, spill in oversize[
            : limit or len(oversize)
        ]:
            print(f"0x{address:08x} {name}")
            print(f"    recorded size {size} (ends 0x{address + size:08x})")
            print(f"    next function       0x{next_address:08x}  {next_name}")
            print(f"    bytes past it       {spill}")
    if padded:
        print("\n-- extents spanning interior alignment padding --")
        padded.sort(key=lambda item: -item[4])
        for address, size, name, pad_at, spill in padded[: limit or len(padded)]:
            print(f"0x{address:08x} {name}")
            print(f"    recorded size {size} (ends 0x{address + size:08x})")
            print(f"    padding run at      0x{pad_at:08x}")
            print(f"    bytes past padding  {spill}")
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
