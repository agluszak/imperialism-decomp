#!/usr/bin/env python3
"""Re-bound existing Ghidra functions in place.

`repair_code_gaps` only *creates* functions Ghidra never made; it skips any
address that already has a function entity. But Ghidra sometimes creates a
function whose body was never disassembled (the entry byte is left as undefined
data), clamping the body to a single byte. Such a function keeps its curated
name yet gives reccmp/decompile a 1-byte compare window — wrong ground truth.

The other shape this fixes is a *punctured* body. When an address that used to
carry its own function is demoted to a plain label, the code it covered is not
handed back to the enclosing function: the enclosing body keeps a hole starting
exactly at the demoted address. Ghidra will happily leave a body that stops
mid-basic-block, so the flow falls straight into unclaimed code. `--force`
re-bounds any named function regardless of its current size, which reabsorbs
those holes.

For each address passed on the command line: disassemble the entry (following
instruction flow) and recompute the body via CreateFunctionCmd.fixupFunctionBody,
which preserves the function's name/namespace and only fixes the extent. Without
`--force` only degenerate (<= 1-byte) functions are touched.

Re-bounding never absorbs another function: a recomputed body that would contain
a second function's entry point is rolled back and reported, so a mis-analysed
neighbour cannot be silently swallowed.

Dry-run by default; pass --apply to write + save. After an --apply run:
`just export-project` then `just refresh-inventory` so the inventory picks up the
real sizes.

usage:
  fix_function_bounds 0xADDR [0xADDR ...] [--force] [--apply]
"""

from __future__ import annotations

import argparse
import sys

from tools.common import ghidra_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("addresses", nargs="+", help="Function entry addresses (0x...).")
    parser.add_argument(
        "--disassemble-tail",
        action="store_true",
        help=(
            "before re-bounding, disassemble the byte just past the body when it is "
            "undefined; needed for functions truncated because their tail was never "
            "turned into instructions"
        ),
    )
    parser.add_argument(
        "--clear-data-holes",
        action="store_true",
        help=(
            "before re-bounding, clear stale DATA units inside body holes and disassemble "
            "them; needed when a data definition masks real code in the middle of a "
            "function (the body then stops at the data and resumes after it)"
        ),
    )
    parser.add_argument(
        "--end",
        type=lambda value: int(value, 16),
        help=(
            "set one listing-verified function body to the inclusive instruction-end "
            "address; refuses non-instruction boundaries and overlapping functions"
        ),
    )
    parser.add_argument("--apply", action="store_true",
                        help="Fix the bounds and save the program (default: dry-run).")
    parser.add_argument("--force", action="store_true",
                        help="Re-bound regardless of current size (repairs punctured bodies).")
    return parser.parse_args()


def body_holes(func):
    """Gaps between the address ranges of a function body, low to high."""
    ranges = [(r.getMinAddress().getOffset(), r.getMaxAddress().getOffset())
              for r in func.getBody().getAddressRanges()]
    ranges.sort()
    return [(ranges[i][1], ranges[i + 1][0]) for i in range(len(ranges) - 1)]


def main() -> int:
    args = parse_args()
    targets = [int(a, 16) for a in args.addresses]

    if args.clear_data_holes and len(targets) > 1:
        # Clearing a hole is only sound once you have looked at the bytes and seen real
        # code (`just ghidra raw-disasm <hole start>`). Run over a batch it also clears
        # holes that were correctly data, and the re-bound then collapses: a 387-byte body
        # became 14 bytes, a 225-byte one became 138, in a single 12-address invocation.
        # One address at a time, deliberately.
        print(
            "--clear-data-holes takes ONE address: verify the hole holds code "
            f"(just ghidra raw-disasm ...) before clearing it; got {len(targets)}.",
            file=sys.stderr,
        )
        return 2
    if args.end is not None and len(targets) != 1:
        print("--end takes exactly ONE function address.", file=sys.stderr)
        return 2

    import pyghidra

    project = ghidra_env.open_project()
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.address import AddressSet

    consumer, program = ghidra_env.open_program(project, writable=args.apply)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        txid = None
        if args.apply:
            txid = program.startTransaction("fix degenerate function bounds")

        fixed, skipped, still_bad = [], [], []
        try:
            for t in targets:
                taddr = af.getAddress(t)
                func = fm.getFunctionAt(taddr)
                if func is None:
                    print(f"  0x{t:08x}  NO FUNCTION at entry — skipped")
                    skipped.append(t)
                    continue
                old_size = func.getBody().getNumAddresses()
                name = func.getName()
                holes = body_holes(func)
                instruction_span_repaired = False
                if old_size > 1 and not args.force:
                    print(f"  0x{t:08x}  already {old_size} bytes ({name}) — skipped"
                          f"{f'; {len(holes)} body hole(s), pass --force' if holes else ''}")
                    skipped.append(t)
                    continue
                if not args.apply:
                    detail = f"{len(holes)} hole(s)" if holes else "contiguous"
                    for lo, hi in holes:
                        detail += f"\n      hole 0x{lo + 1:08x}-0x{hi - 1:08x}"
                    print(f"  0x{t:08x}  {old_size} bytes ({name}) — would re-bound; {detail}")
                    continue
                if listing.getInstructionAt(taddr) is None:
                    DisassembleCommand(taddr, None, True).applyTo(program, pyghidra.task_monitor())
                if args.disassemble_tail:
                    # A body that stops mid-function because the bytes after it were never
                    # disassembled cannot be re-bound on its own: fixupFunctionBody follows
                    # existing instruction flow, and undefined data offers nothing to follow.
                    # Disassembling the boundary first gives the flow somewhere to go. The
                    # swallow guard below still protects a mis-analysed neighbour.
                    boundary = func.getBody().getMaxAddress().next()
                    if boundary is not None and listing.getInstructionAt(boundary) is None:
                        DisassembleCommand(boundary, None, True).applyTo(
                            program, pyghidra.task_monitor()
                        )
                if args.clear_data_holes:
                    # A defined DATA unit sitting on real code splits the body in two: the
                    # flow that fixupFunctionBody follows stops at the data and picks up
                    # again after it. Clearing the data and disassembling the hole hands
                    # those bytes back. Holes that overlap another function are left alone
                    # so this can never cannibalise a neighbour.
                    for lo, hi in body_holes(func):
                        start = af.getAddress(lo + 1)
                        end = af.getAddress(hi - 1)
                        if start.getOffset() > end.getOffset():
                            continue
                        owner = fm.getFunctionContaining(start)
                        if owner is not None and owner.getEntryPoint().getOffset() != t:
                            print(f"      hole 0x{lo + 1:08x}-0x{hi - 1:08x}: owned by "
                                  f"0x{owner.getEntryPoint().getOffset():08x} — left alone")
                            continue
                        if listing.getDefinedDataAt(start) is None and (
                            listing.getInstructionAt(start) is not None
                        ):
                            continue
                        # Ghidra clears whole code units. A data item that STRADDLES the
                        # hole's end therefore takes body bytes with it, and the re-
                        # disassembly desynchronises from there: two 1-byte holes whose
                        # dword ran into the body collapsed a 387-byte function to 14 and
                        # a 225-byte one to 138. Refuse instead; those need the data item
                        # re-typed first, which is a separate decision.
                        straddler = None
                        cursor = listing.getCodeUnitContaining(start)
                        while cursor is not None and cursor.getMinAddress().getOffset() <= hi - 1:
                            if cursor.getMaxAddress().getOffset() > hi - 1:
                                straddler = cursor
                                break
                            next_address = cursor.getMaxAddress().next()
                            if next_address is None:
                                break
                            cursor = listing.getCodeUnitContaining(next_address)
                        if straddler is not None:
                            print(
                                f"      hole 0x{lo + 1:08x}-0x{hi - 1:08x}: a code unit at "
                                f"0x{straddler.getMinAddress().getOffset():08x} runs past the "
                                "hole into the body — refusing to clear (re-type it first)"
                            )
                            continue
                        listing.clearCodeUnits(start, end, False)
                        DisassembleCommand(start, None, True).applyTo(
                            program, pyghidra.task_monitor()
                        )
                        print(f"      hole 0x{lo + 1:08x}-0x{hi - 1:08x}: cleared + disassembled")
                before = func.getBody()
                if args.end is not None:
                    end = af.getAddress(args.end)
                    candidate = AddressSet(taddr, end)
                    overlaps = [
                        other.getEntryPoint().getOffset()
                        for other in fm.getFunctionsOverlapping(candidate)
                        if other.getEntryPoint().getOffset() != t
                    ]
                    if overlaps:
                        print(f"  0x{t:08x}  REFUSED ({name}): explicit body overlaps "
                              + ", ".join(f"0x{s:08x}" for s in sorted(overlaps)))
                        still_bad.append(t)
                        continue
                    cursor = taddr
                    first_gap = None
                    while cursor is not None and cursor.compareTo(end) <= 0:
                        instruction = listing.getInstructionAt(cursor)
                        if instruction is None:
                            first_gap = cursor
                            break
                        cursor = instruction.getMaxAddress().next()
                    if first_gap is not None:
                        if not args.clear_data_holes:
                            print(
                                f"  0x{t:08x}  REFUSED ({name}): explicit body has a "
                                f"non-instruction byte at 0x{first_gap.getOffset():08x}; "
                                "inspect raw bytes, then pass --clear-data-holes"
                            )
                            still_bad.append(t)
                            continue
                        listing.clearCodeUnits(first_gap, end, False)
                        DisassembleCommand(first_gap, None, True).applyTo(
                            program, pyghidra.task_monitor()
                        )
                        instruction_span_repaired = True
                        print(
                            f"      span 0x{first_gap.getOffset():08x}-0x{args.end:08x}: "
                            "cleared + disassembled"
                        )
                    cursor = taddr
                    while cursor is not None and cursor.compareTo(end) <= 0:
                        instruction = listing.getInstructionAt(cursor)
                        if instruction is None:
                            break
                        cursor = instruction.getMaxAddress().next()
                    final_instruction = listing.getInstructionContaining(end)
                    if cursor is None or cursor.compareTo(end.next()) != 0 or (
                        final_instruction is None or final_instruction.getMaxAddress() != end
                    ):
                        print(
                            f"  0x{t:08x}  REFUSED ({name}): --end 0x{args.end:08x} "
                            "does not produce a continuous instruction body"
                        )
                        still_bad.append(t)
                        continue
                    func.setBody(candidate)
                else:
                    CreateFunctionCmd.fixupFunctionBody(program, func, pyghidra.task_monitor())
                # Never let a re-bound body swallow a neighbouring function.
                swallowed = [
                    other.getEntryPoint().getOffset()
                    for other in fm.getFunctionsOverlapping(func.getBody())
                    if other.getEntryPoint().getOffset() != t
                ]
                if swallowed:
                    func.setBody(before)
                    print(f"  0x{t:08x}  ROLLED BACK ({name}): would swallow "
                          + ", ".join(f"0x{s:08x}" for s in sorted(swallowed)))
                    still_bad.append(t)
                    continue
                new_size = func.getBody().getNumAddresses()
                if new_size > 1 and (new_size != old_size or instruction_span_repaired):
                    size_change = f"{old_size} -> {new_size} bytes"
                    if new_size == old_size:
                        size_change = f"{new_size} bytes; instruction span repaired"
                    print(f"  0x{t:08x}  {size_change} ({name}); "
                          f"holes {len(holes)} -> {len(body_holes(func))}")
                    fixed.append(t)
                elif new_size > 1:
                    print(f"  0x{t:08x}  unchanged at {new_size} bytes ({name})")
                    skipped.append(t)
                else:
                    print(f"  0x{t:08x}  STILL 1 byte after fixup ({name})")
                    still_bad.append(t)
        finally:
            if txid is not None:
                program.endTransaction(txid, True)

        if not args.apply:
            print("dry-run; pass --apply to re-bound + save")
            return 0

        print(f"fixed: {len(fixed)}  skipped: {len(skipped)}  still-bad: {len(still_bad)}")
        if fixed:
            program.getDomainFile().save(pyghidra.task_monitor())
            print("saved program — now run `just export-project` and `just refresh-inventory`")
        return 1 if still_bad else 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    sys.exit(main())
