#!/usr/bin/env python3
"""Delete stray Function entities in the ILT jmp-thunk range from the Ghidra DB.

The start of .text (0x401000..) is a contiguous table of incremental-link 5-byte
``jmp <real body>`` stubs. reccmp resolves vtable slots and calls *through* these
thunks only while they stay unannotated in both binaries; a Function entity
defined on one (left by auto-analysis, an import pass, or repair-code-gaps)
blocks reccmp's thunk auto-resolution and collapses vtable matching (~400
functions lost 100% in the 2026-07 gap-repair attempt; the fix then was manual
``FunctionManager.removeFunction`` surgery — see docs/ghidra-db-mutations.md).

``just prune-ilt-thunks`` cleans the symbols.csv side; this tool cleans the DB
side. ``just sync-ghidra`` runs it with --apply before the export so a resync
can never re-introduce the entities.

Only functions whose entry lies inside the exe-derived contiguous ILT region
*and* whose entry instruction is an unconditional JMP are touched, and the same
keep-rules as the csv-side prune apply (address claimed by a manual marker, or
symbol name referenced by manual source — those autogen stubs must keep
linking). Read-only by default; --apply removes the rest and saves the DB.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.workflow.prune_ilt_thunks import (
    TextSection,
    collect_claimed_addresses,
    collect_manual_text,
    ilt_keep_reason,
    original_exe_from_user_yml,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove Function entities on ILT jmp thunks from the Ghidra DB."
    )
    parser.add_argument(
        "--apply", action="store_true", help="Write changes to the Ghidra DB (default: dry-run)."
    )
    parser.add_argument(
        "--original-exe",
        default=None,
        help="Path to the original Imperialism.exe (default: from reccmp-user.yml)",
    )
    parser.add_argument("--quiet", action="store_true", help="Don't list each removed function.")
    return parser.parse_args()


def run(program, args, ilt_lo: int, ilt_hi: int, repo_root) -> dict:
    fm = program.getFunctionManager()
    listing = program.getListing()
    factory = program.getAddressFactory()
    af = factory.getDefaultAddressSpace()

    claimed = collect_claimed_addresses(repo_root)
    manual_text = collect_manual_text(repo_root)

    to_remove = []
    kept_non_jmp = 0
    kept_in_use = 0
    span = factory.getAddressSet(af.getAddress(ilt_lo), af.getAddress(ilt_hi))
    for fn in fm.getFunctions(span, True):
        entry = fn.getEntryPoint()
        instr = listing.getInstructionAt(entry)
        # Only ever delete a genuine 5-byte jmp stub; anything else in the range
        # (there should be nothing) is left for a human to look at.
        if instr is None or not str(instr.getMnemonicString()).upper().startswith("JMP"):
            kept_non_jmp += 1
            continue
        offset = int(entry.getOffset())
        name = str(fn.getName())
        if ilt_keep_reason(offset, name, claimed, manual_text) is not None:
            kept_in_use += 1
            continue
        to_remove.append((offset, name))

    removed = 0
    if args.apply:
        for offset, _name in to_remove:
            fm.removeFunction(af.getAddress(offset))
            removed += 1

    return {
        "candidates": to_remove,
        "removed": removed,
        "kept_non_jmp": kept_non_jmp,
        "kept_in_use": kept_in_use,
    }


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=2)
    exe_path = (
        Path(args.original_exe) if args.original_exe else original_exe_from_user_yml(repo_root)
    )
    text = TextSection(exe_path.read_bytes())
    ilt_lo, ilt_hi = text.ilt_region()

    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        if args.apply:
            txid = program.startTransaction("prune ILT-range function entities")
        result = run(program, args, ilt_lo, ilt_hi, repo_root)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("prune ILT-range function entities", pyghidra.task_monitor())

        mode = "APPLIED" if args.apply else "DRY RUN"
        if not args.quiet:
            for offset, name in result["candidates"][:5000]:
                print(f"  0x{offset:08x}  {name}")
        print(
            f"[{mode}] ILT region 0x{ilt_lo:08x}..0x{ilt_hi:08x}: "
            f"{len(result['candidates'])} jmp-thunk function entities"
            + (f", removed {result['removed']}" if args.apply else " would be removed")
            + (f", kept {result['kept_in_use']} claimed/referenced" if result["kept_in_use"] else "")
            + (f", kept {result['kept_non_jmp']} non-jmp entries" if result["kept_non_jmp"] else "")
        )
        if not args.apply and result["candidates"]:
            print("Re-run with --apply to remove them (sync-ghidra does this automatically).")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
