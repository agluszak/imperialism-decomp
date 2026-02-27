#!/usr/bin/env python3
"""
Delete function(s) at explicit addresses.

Usage:
  .venv/bin/python new_scripts/delete_function_at.py 0x00402c20 --apply
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
    t = text.strip().lower()
    if t.startswith("0x"):
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
    ap.add_argument("addresses", nargs="+", help="Function entry addresses (hex)")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    targets = [parse_hex(x) for x in args.addresses]
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        plans = []
        for a in targets:
            f = fm.getFunctionAt(af.getAddress(f"0x{a:08x}"))
            if f is None:
                print(f"[miss] 0x{a:08x}")
                continue
            plans.append((a, f))
            print(f"[plan] 0x{a:08x} {f.getName()} :: {f.getSignature()}")

        if not args.apply:
            print("[dry-run] pass --apply to delete")
            return 0

        tx = program.startTransaction("Delete function at addresses")
        ok = fail = 0
        try:
            for a, f in plans:
                try:
                    fm.removeFunction(f.getEntryPoint())
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{a:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)
        program.save("delete function at addresses", None)
        print(f"[done] ok={ok} fail={fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

