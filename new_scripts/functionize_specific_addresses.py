#!/usr/bin/env python3
"""
Create functions at specific addresses (if missing).

Usage:
  .venv/bin/python new_scripts/functionize_specific_addresses.py \
    --address 0x004036ca --address 0x00406a37 --apply
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
    ap.add_argument("--address", action="append", required=True, help="Address to functionize")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    addrs = sorted(set(parse_hex(x) for x in args.address))
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.flatapi import FlatProgramAPI

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        api = FlatProgramAPI(program)

        print(f"[plan] addresses={len(addrs)} apply={args.apply}")
        for a in addrs:
            addr = af.getAddress(f"0x{a:08x}")
            fn = fm.getFunctionAt(addr)
            if fn is None:
                fn = fm.getFunctionContaining(addr)
            if fn is None:
                print(f"  0x{a:08x} -> <missing>")
            else:
                print(f"  0x{a:08x} -> {fn.getEntryPoint()} {fn.getName()}")

        if not args.apply:
            print("[dry-run] pass --apply to create functions")
            return 0

        tx = program.startTransaction("Functionize specific addresses")
        created = skipped = failed = 0
        try:
            for a in addrs:
                addr = af.getAddress(f"0x{a:08x}")
                if fm.getFunctionContaining(addr) is not None:
                    skipped += 1
                    continue
                try:
                    api.disassemble(addr)
                    fn = api.createFunction(addr, None)
                    if fn is None and fm.getFunctionContaining(addr) is None:
                        failed += 1
                    else:
                        created += 1
                except Exception as ex:
                    failed += 1
                    print(f"[fail] 0x{a:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("functionize specific addresses", None)
        print(f"[done] created={created} skipped={skipped} failed={failed}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
