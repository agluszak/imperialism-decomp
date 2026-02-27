#!/usr/bin/env python3
"""
Bulk functionize missing branch targets in executable memory.

Candidate rule:
- source instruction is CALL or JMP with exactly one flow target
- target is inside executable memory
- no function currently contains target
- optional address window filter

Usage:
  .venv/bin/python new_scripts/functionize_missing_branch_targets.py
  .venv/bin/python new_scripts/functionize_missing_branch_targets.py --apply
  .venv/bin/python new_scripts/functionize_missing_branch_targets.py --apply --max-create 0
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write new functions")
    ap.add_argument(
        "--max-create",
        type=int,
        default=500,
        help="Maximum created functions when --apply (0 = unlimited)",
    )
    ap.add_argument(
        "--max-print",
        type=int,
        default=300,
        help="Maximum candidates to print",
    )
    ap.add_argument("--start", default="", help="Optional scan start address (hex)")
    ap.add_argument("--end", default="", help="Optional scan end address (hex, exclusive)")
    ap.add_argument(
        "--mnemonics",
        default="CALL,JMP",
        help="Comma-separated branch mnemonics to consider",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    mnemonics = {m.strip().upper() for m in args.mnemonics.split(",") if m.strip()}
    start_int = parse_hex(args.start) if args.start else None
    end_int = parse_hex(args.end) if args.end else None

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.flatapi import FlatProgramAPI

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()
        api = FlatProgramAPI(program)

        candidates: list[tuple[int, int, str, str]] = []
        seen_dst: set[int] = set()

        it = listing.getInstructions(True)
        while it.hasNext():
            ins = it.next()
            src_addr = ins.getAddress()
            src = src_addr.getOffset() & 0xFFFFFFFF

            if start_int is not None and src < start_int:
                continue
            if end_int is not None and src >= end_int:
                continue

            mnem = str(ins.getMnemonicString()).upper()
            if mnem not in mnemonics:
                continue

            flows = ins.getFlows()
            if flows is None or len(flows) != 1:
                continue

            dst_addr = flows[0]
            dst = dst_addr.getOffset() & 0xFFFFFFFF
            if dst in seen_dst:
                continue
            seen_dst.add(dst)

            block = mem.getBlock(dst_addr)
            if block is None or not block.isExecute():
                continue
            if str(dst_addr).startswith("EXTERNAL:"):
                continue
            if fm.getFunctionContaining(dst_addr) is not None:
                continue

            src_fn = fm.getFunctionContaining(src_addr)
            src_name = src_fn.getName() if src_fn is not None else "<no_func>"
            candidates.append((src, dst, mnem, src_name))

        candidates.sort(key=lambda t: t[1])
        print(
            "[summary] "
            f"candidates={len(candidates)} "
            f"mnemonics={','.join(sorted(mnemonics))} "
            f"range_start={args.start or '<none>'} "
            f"range_end={args.end or '<none>'}"
        )
        for src, dst, mnem, src_name in candidates[: args.max_print]:
            print(f"src=0x{src:08x} {mnem} -> dst=0x{dst:08x} caller={src_name}")
        if len(candidates) > args.max_print:
            print(f"... ({len(candidates) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to create functions")
            return 0

        tx = program.startTransaction("Functionize missing branch targets")
        created = 0
        skipped = 0
        failed = 0
        limit = args.max_create

        try:
            for _src, dst, _mnem, _src_name in candidates:
                if limit > 0 and created >= limit:
                    break
                dst_addr = af.getAddress(f"0x{dst:08x}")

                # Re-check after any prior creations in this pass.
                if fm.getFunctionContaining(dst_addr) is not None:
                    skipped += 1
                    continue

                try:
                    api.disassemble(dst_addr)
                    fn = api.createFunction(dst_addr, None)
                    if fn is None:
                        if fm.getFunctionContaining(dst_addr) is not None:
                            created += 1
                        else:
                            skipped += 1
                    else:
                        created += 1
                except Exception as ex:
                    failed += 1
                    print(f"[fail] dst=0x{dst:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("functionize missing branch targets", None)
        print(
            "[done] "
            f"created={created} skipped={skipped} failed={failed} "
            f"limit={args.max_create}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
