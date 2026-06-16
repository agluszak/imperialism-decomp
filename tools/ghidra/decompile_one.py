#!/usr/bin/env python3
"""Read-only pyghidra driver: decompile one function by address.

Usage:
  uv run python -m tools.ghidra.decompile_one 0x004DB380 [0x...]

Opens the Ghidra project read-only, runs the decompiler on each requested
address, and prints the C output plus the listing-level signature. Intended
as a scratch tool for active reverse-engineering, not part of the build.
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env


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

    project = ghidra_env.open_project()
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)

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
            try:
                all_params = fn.getAllParameters()
            except Exception:  # noqa: BLE001
                all_params = fn.getParameters()
            if all_params:
                print("  params:")
                for param in all_params:
                    auto = " auto" if getattr(param, "isAutoParameter", lambda: False)() else ""
                    dt = param.getDataType()
                    try:
                        path = dt.getDataTypePath()
                    except Exception:  # noqa: BLE001
                        path = "<no path>"
                    print(f"    {param.getName()}: {dt}{auto} [{dt.getClass().getName()} {path}]")
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
