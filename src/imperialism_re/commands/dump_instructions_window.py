#!/usr/bin/env python3
"""
Dump linear instruction windows around raw addresses.

Usage:
  uv run impk dump_instructions_window \
    --address 0x00415e25 --address 0x0047f715 --before 20 --after 30
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def nearest_instruction(listing, addr):
    ins = listing.getInstructionAt(addr)
    if ins is not None:
        return ins
    before = listing.getInstructionBefore(addr)
    after = listing.getInstructionAfter(addr)
    if before is None:
        return after
    if after is None:
        return before
    d_before = addr.getOffset() - before.getAddress().getOffset()
    d_after = after.getAddress().getOffset() - addr.getOffset()
    return before if d_before <= d_after else after

def instruction_contains(ins, addr_int: int) -> bool:
    start = ins.getAddress().getOffset() & 0xFFFFFFFF
    end = ins.getMaxAddress().getOffset() & 0xFFFFFFFF
    return start <= addr_int <= end

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", action="append", required=True, help="Address to inspect")
    ap.add_argument("--before", type=int, default=16, help="Instructions before center")
    ap.add_argument("--after", type=int, default=24, help="Instructions after center")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    addrs = sorted(set(parse_hex(a) for a in args.address))
    root = resolve_project_root(args.project_root)

    with open_program(root) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        for addr_int in addrs:
            addr = af.getAddress(f"0x{addr_int:08x}")
            center = nearest_instruction(listing, addr)
            print(f"\n=== 0x{addr_int:08x} ===")
            if center is None:
                print("no nearby instruction")
                continue

            # Walk backward
            seq = [center]
            cur = center
            for _ in range(max(0, args.before)):
                cur = listing.getInstructionBefore(cur.getAddress())
                if cur is None:
                    break
                seq.append(cur)
            seq.reverse()

            # Walk forward
            cur = center
            for _ in range(max(0, args.after)):
                cur = listing.getInstructionAfter(cur.getAddress())
                if cur is None:
                    break
                seq.append(cur)

            # Function context of the inspected raw address.
            owner = fm.getFunctionContaining(addr)
            if owner is None:
                print("owner: <no_func>")
            else:
                print(f"owner: {owner.getEntryPoint()} {owner.getName()}")

            for ins in seq:
                mark = ">>" if instruction_contains(ins, addr_int) else "  "
                print(f"{mark} {ins.getAddress()}: {ins}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
