#!/usr/bin/env python3
"""
Inspect potential thunk/stub entry addresses and resolve first flow target.

Usage:
  .venv/bin/python new_scripts/inspect_entry_stub_targets.py <addr_hex> [addr_hex...]
  .venv/bin/python new_scripts/inspect_entry_stub_targets.py --create <addr_hex> [...]

Output columns:
  address,function,first_instruction,flow_target,target_function,created_function
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
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--create", action="store_true", help="Create function if missing")
    ap.add_argument("addresses", nargs="+")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    addrs = [parse_hex(a) for a in args.addresses]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        monitor = ConsoleTaskMonitor()

        tx = program.startTransaction("Inspect entry stub targets")
        modified = False
        try:
            print("address,function,first_instruction,flow_target,target_function,created_function")
            for a in addrs:
                addr = af.getAddress(f"0x{a:08x}")
                func = fm.getFunctionAt(addr)
                created_name = ""

                if func is None:
                    # Ensure at least one instruction exists for inspection.
                    DisassembleCommand(addr, None, True).applyTo(program, monitor)
                    if args.create:
                        CreateFunctionCmd(None, addr, None, SourceType.USER_DEFINED).applyTo(
                            program, monitor
                        )
                        func = fm.getFunctionAt(addr)
                        if func is not None:
                            created_name = func.getName()
                            modified = True

                ins = listing.getInstructionAt(addr)
                ins_text = str(ins) if ins is not None else "<no_inst>"
                flow_target = ""
                target_name = ""
                if ins is not None:
                    flows = ins.getFlows()
                    if flows is not None and len(flows) > 0:
                        ft = flows[0]
                        flow_target = str(ft)
                        tf = fm.getFunctionAt(ft)
                        if tf is not None:
                            target_name = tf.getName()

                func_name = func.getName() if func is not None else "<none>"
                print(
                    f"0x{a:08x},{func_name},\"{ins_text}\",{flow_target},{target_name},{created_name}"
                )
        finally:
            program.endTransaction(tx, True)

        if modified:
            program.save("inspect/create entry stubs", None)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
