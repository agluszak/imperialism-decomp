#!/usr/bin/env python3
"""
Dump linear instruction windows around raw addresses.

Usage:
  .venv/bin/python new_scripts/dump_instructions_window.py \
    --address 0x00415e25 --address 0x0047f715 --before 20 --after 30
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


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
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    addrs = sorted(set(parse_hex(a) for a in args.address))
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
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
