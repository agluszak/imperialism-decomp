#!/usr/bin/env python3
"""
Create and rename missing JMP-thunk functions from CSV rows.

Usage:
  .venv/bin/python new_scripts/create_specific_jmp_thunks_from_csv.py \
      <in_csv> [project_root]

CSV columns:
  - source_addr OR address   (required)
  - target_addr              (optional, verification)
  - new_name                 (optional)
  - target_name              (optional, fallback for new_name as thunk_<target_name>)
  - comment                  (optional, plate comment at thunk entry)
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_hex(text: str) -> int:
    t = text.strip()
    if not t:
        raise ValueError("empty hex token")
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def is_generic(name: str) -> bool:
    return bool(re.match(r"^(FUN_|thunk_FUN_)", name))


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: create_specific_jmp_thunks_from_csv.py <in_csv> [project_root]"
        )
        return 1

    root = Path(__file__).resolve().parents[1]
    in_csv = Path(sys.argv[1])
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if len(sys.argv) >= 3:
        root = Path(sys.argv[2]).resolve()

    if not in_csv.exists():
        print(f"[err] missing csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    if not rows:
        print(f"[err] empty csv: {in_csv}")
        return 1

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    ok = 0
    created = 0
    skipped = 0
    failed = 0

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.listing import CodeUnit
        from ghidra.util.task import ConsoleTaskMonitor

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()
        monitor = ConsoleTaskMonitor()

        tx = program.startTransaction("Create/rename specific JMP thunks from CSV")
        try:
            for row in rows:
                src_raw = (row.get("source_addr") or row.get("address") or "").strip()
                if not src_raw:
                    skipped += 1
                    continue

                try:
                    src_int = parse_hex(src_raw)
                except Exception:
                    failed += 1
                    print(f"[fail] bad source addr: {src_raw}")
                    continue

                src = af.getAddress(f"0x{src_int:08x}")
                ins = listing.getInstructionAt(src)
                if ins is None:
                    block = mem.getBlock(src)
                    if block is None or not block.isExecute():
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: non-executable source")
                        continue
                    # Some vtable-target stubs live in undecoded islands; force decode first.
                    listing.clearCodeUnits(src, src, False)
                    if not DisassembleCommand(src, None, True).applyTo(program, monitor):
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: disassemble failed")
                        continue
                    ins = listing.getInstructionAt(src)
                    if ins is None:
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: no instruction after disassemble")
                        continue
                if str(ins.getMnemonicString()).upper() != "JMP":
                    failed += 1
                    print(
                        f"[fail] 0x{src_int:08x}: not JMP ({ins.getMnemonicString()})"
                    )
                    continue
                flows = ins.getFlows()
                if flows is None or len(flows) != 1:
                    failed += 1
                    print(f"[fail] 0x{src_int:08x}: non-single-flow JMP")
                    continue
                dst = flows[0]

                expected_target = (row.get("target_addr") or "").strip()
                if expected_target:
                    try:
                        exp_int = parse_hex(expected_target)
                        exp_addr = af.getAddress(f"0x{exp_int:08x}")
                        if dst != exp_addr:
                            failed += 1
                            print(
                                f"[fail] 0x{src_int:08x}: target mismatch "
                                f"(actual={dst}, expected={exp_addr})"
                            )
                            continue
                    except Exception:
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: bad target_addr {expected_target}")
                        continue

                target_fn = fm.getFunctionAt(dst)
                target_name = (
                    (row.get("target_name") or "").strip()
                    or (target_fn.getName() if target_fn is not None else "")
                )
                new_name = (row.get("new_name") or "").strip()
                if not new_name and target_name and not is_generic(target_name):
                    new_name = f"thunk_{target_name}"
                if not new_name:
                    skipped += 1
                    print(f"[skip] 0x{src_int:08x}: no new_name available")
                    continue

                fn = fm.getFunctionAt(src)
                if fn is None:
                    block = mem.getBlock(src)
                    if block is None or not block.isExecute():
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: non-executable source")
                        continue
                    program.getListing().clearCodeUnits(src, src, False)
                    if not DisassembleCommand(src, None, True).applyTo(program, monitor):
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: disassemble failed")
                        continue
                    CreateFunctionCmd(None, src, None, SourceType.USER_DEFINED).applyTo(
                        program, monitor
                    )
                    fn = fm.getFunctionAt(src)
                    if fn is None:
                        failed += 1
                        print(f"[fail] 0x{src_int:08x}: createFunction failed")
                        continue
                    created += 1

                try:
                    fn.setName(new_name, SourceType.USER_DEFINED)
                except Exception as ex:
                    failed += 1
                    print(f"[fail] 0x{src_int:08x}: rename failed: {ex}")
                    continue

                comment = (row.get("comment") or "").strip()
                if comment:
                    listing.setComment(src, CodeUnit.PLATE_COMMENT, comment)

                ok += 1
                print(
                    f"[ok] 0x{src_int:08x}: {new_name} -> {dst}"
                )

            program.endTransaction(tx, True)
            program.save("create_specific_jmp_thunks_from_csv", None)
        except Exception:
            program.endTransaction(tx, False)
            raise

    print(
        f"[done] rows={len(rows)} ok={ok} created={created} skipped={skipped} fail={failed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
