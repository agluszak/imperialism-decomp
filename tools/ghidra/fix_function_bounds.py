#!/usr/bin/env python3
"""Re-bound existing degenerate (1-byte) Ghidra functions in place.

`repair_code_gaps` only *creates* functions Ghidra never made; it skips any
address that already has a function entity. But Ghidra sometimes creates a
function whose body was never disassembled (the entry byte is left as undefined
data), clamping the body to a single byte. Such a function keeps its curated
name yet gives reccmp/decompile a 1-byte compare window — wrong ground truth.

For each address passed on the command line: if a function exists there with a
<= 1-byte body, disassemble the entry (following instruction flow) and recompute
the body via CreateFunctionCmd.fixupFunctionBody, which preserves the function's
name/namespace and only fixes the extent. Dry-run by default; pass --apply to
write + save. After an --apply run: `just export-project` then `just refresh-inventory`
so symbols.csv picks up the real sizes.

usage:
  fix_function_bounds 0xADDR [0xADDR ...] [--apply]
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
    return parser.parse_args()


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
                if old_size > 1:
                    print(f"  0x{t:08x}  already {old_size} bytes ({name}) — skipped")
                    skipped.append(t)
                    continue
                if not args.apply:
                    print(f"  0x{t:08x}  {old_size}-byte ({name}) — would re-bound")
                    continue
                if listing.getInstructionAt(taddr) is None:
                    DisassembleCommand(taddr, None, True).applyTo(program, pyghidra.task_monitor())
                CreateFunctionCmd.fixupFunctionBody(program, func, pyghidra.task_monitor())
                new_size = func.getBody().getNumAddresses()
                if new_size > 1:
                    print(f"  0x{t:08x}  {old_size} -> {new_size} bytes ({name})")
                    fixed.append(t)
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
