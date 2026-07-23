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

    import pyghidra

    project = ghidra_env.open_project()
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd

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
                before = func.getBody()
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
                if new_size > 1 and new_size != old_size:
                    print(f"  0x{t:08x}  {old_size} -> {new_size} bytes ({name}); "
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
