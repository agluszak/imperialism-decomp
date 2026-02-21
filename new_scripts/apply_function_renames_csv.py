#!/usr/bin/env python3
"""
Apply function renames from CSV.

CSV columns:
  address,new_name[,comment]

Usage:
  .venv/bin/python new_scripts/apply_function_renames_csv.py <csv_path> [project_root]
"""

from __future__ import annotations

import csv
import sys
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
    if len(sys.argv) < 2:
        print("usage: apply_function_renames_csv.py <csv_path> [project_root]")
        return 1

    csv_path = Path(sys.argv[1])
    root = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path(__file__).resolve().parents[1]
    if not csv_path.exists():
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8")))
    if not rows:
        print("no rows")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        tx = program.startTransaction("Apply function renames from CSV")
        ok = skip = fail = cmt = 0
        try:
            for row in rows:
                addr_txt = (row.get("address") or "").strip()
                new_name = (row.get("new_name") or "").strip()
                comment = (row.get("comment") or "").strip()
                if not addr_txt or not new_name:
                    fail += 1
                    print(f"[row-fail] missing address/new_name row={row}")
                    continue

                try:
                    addr_int = parse_hex(addr_txt)
                except Exception as ex:
                    fail += 1
                    print(f"[addr-fail] {addr_txt} err={ex}")
                    continue

                addr = af.getAddress(f"0x{addr_int:08x}")
                func = fm.getFunctionAt(addr)
                if func is None:
                    fail += 1
                    print(f"[miss] no function at 0x{addr_int:08x}")
                    continue

                if func.getName() == new_name:
                    skip += 1
                else:
                    try:
                        func.setName(new_name, SourceType.USER_DEFINED)
                        ok += 1
                    except Exception as ex:
                        fail += 1
                        print(f"[rename-fail] 0x{addr_int:08x} -> {new_name} err={ex}")
                        continue

                if comment:
                    try:
                        func.setComment(comment)
                        cmt += 1
                    except Exception as ex:
                        print(f"[comment-fail] 0x{addr_int:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply function renames from csv", None)
        print(f"[done] rows={len(rows)} ok={ok} skip={skip} fail={fail} comments={cmt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
