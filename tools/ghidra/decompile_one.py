#!/usr/bin/env python3
"""Read-only pyghidra driver: decompile one function by address.

Usage:
  uv run python -m tools.ghidra.decompile_one 0x004DB380 [0x...]

Opens the Ghidra project read-only, runs the decompiler on each requested
address, and prints the C output plus the listing-level signature. Intended
as a scratch tool for active reverse-engineering, not part of the build.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyghidra

PROJECT_LOCATION = os.getenv(
    "GHIDRA_PROJECT_DIR",
    "/home/agluszak/code/decomp/imperialism_knowledge",
)
PROJECT_NAME = os.getenv("GHIDRA_PROJECT_NAME", "imperialism-decomp")
PROGRAM_NAME = os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe")
INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")


def parse_addrs(argv: list[str]) -> list[int]:
    out: list[int] = []
    for a in argv:
        out.append(int(a, 16) if a.lower().startswith("0x") else int(a, 16))
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: decompile_one 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2
    addrs = parse_addrs(sys.argv[1:])

    pyghidra.start(install_dir=Path(INSTALL_DIR) if INSTALL_DIR else None)
    project = pyghidra.open_project(PROJECT_LOCATION, PROJECT_NAME, create=False)
    from java.lang import Object as JavaObject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    consumer = JavaObject()
    program = None
    try:
        program_path = PROGRAM_NAME if PROGRAM_NAME.startswith("/") else f"/{PROGRAM_NAME}"
        domain_file = project.getProjectData().getFile(program_path)
        if domain_file is None:
            raise FileNotFoundError(f'Program "{PROGRAM_NAME}" not found in project.')
        program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())

        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        from ghidra.app.decompiler import DecompileOptions

        ifc = DecompInterface()
        opts = DecompileOptions()
        ifc.setOptions(opts)
        ifc.setSimplificationStyle("decompile")
        if not ifc.openProgram(program):
            print(f"openProgram FAILED: {ifc.getLastMessage()}", file=sys.stderr)
            return 1
        mon = ConsoleTaskMonitor()

        for addr_int in addrs:
            addr = af.getAddress(addr_int)
            fn = fm.getFunctionContaining(addr)
            print("=" * 72)
            if fn is None:
                print(f"0x{addr_int:08x}: no function")
                continue
            print(f"0x{addr_int:08x}  {fn.getName()}  entry={fn.getEntryPoint()}")
            print(f"  signature: {fn.getSignature(True).getPrototypeString()}")
            print(f"  size: {fn.getBody().getNumAddresses()} bytes  calling-conv: {fn.getCallingConventionName()}")
            res = ifc.decompileFunction(fn, 60, mon)
            if not res.decompileCompleted():
                print(f"  DECOMP FAILED: {res.getErrorMessage()}")
                continue
            print(res.getDecompiledFunction().getC())
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
