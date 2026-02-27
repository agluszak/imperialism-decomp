#!/usr/bin/env python3
"""
Apply function renames from CSV.

CSV columns:
  address,new_name[,comment]

Usage:
  uv run impk apply_function_renames_csv [--create-missing] <csv_path> [--project-root <path>]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--create-missing", action="store_true")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument("csv_path")
    args = ap.parse_args()

    create_missing = args.create_missing
    csv_path = Path(args.csv_path)
    root = resolve_project_root(args.project_root)
    if not csv_path.exists():
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8")))
    if not rows:
        print("no rows")
        return 0

    with open_program(root) as program:
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        monitor = ConsoleTaskMonitor()

        tx = program.startTransaction("Apply function renames from CSV")
        ok = skip = fail = cmt = created = 0
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
                    if create_missing:
                        try:
                            DisassembleCommand(addr, None, True).applyTo(program, monitor)
                            CreateFunctionCmd(None, addr, None, SourceType.USER_DEFINED).applyTo(
                                program, monitor
                            )
                            func = fm.getFunctionAt(addr)
                            if func is not None:
                                created += 1
                        except Exception as ex:
                            print(f"[create-fail] 0x{addr_int:08x} err={ex}")
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
        print(
            f"[done] rows={len(rows)} ok={ok} skip={skip} fail={fail} "
            f"comments={cmt} created={created} create_missing={create_missing}"
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
