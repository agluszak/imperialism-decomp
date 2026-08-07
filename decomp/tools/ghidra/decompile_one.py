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
from tools.common.thunk_names import ThunkResolver


def parse_addrs(argv: list[str]) -> list[int]:
    out: list[int] = []
    for a in argv:
        out.append(int(a, 16) if a.lower().startswith("0x") else int(a, 16))
    return out


def make_resolve_real_function(program):
    """Return a closure that follows thunk/jmp chains to the real function."""
    fm = program.getFunctionManager()
    listing = program.getListing()

    def resolve_real_function(start_addr):
        curr = start_addr
        for _ in range(8):
            fn = fm.getFunctionContaining(curr)
            if fn is not None:
                if fn.isThunk():
                    tf = fn.getThunkedFunction(True)
                    if tf is not None:
                        curr = tf.getEntryPoint()
                        continue
                ins = listing.getInstructionAt(fn.getEntryPoint())
                if ins is not None and ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                    curr = ins.getFlows()[0]
                    continue
                return fn
            ins = listing.getInstructionAt(curr)
            if ins is not None and ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                curr = ins.getFlows()[0]
                continue
            break
        return fm.getFunctionContaining(curr)

    return resolve_real_function


def build_thunk_map(program) -> dict[str, str]:
    """Build the ``thunk_name -> real_name`` map from the Ghidra DB.

    A function is treated as a thunk source if Ghidra marks it ``isThunk()`` or if
    its entry is a lone ``jmp`` to a single target (a linker jmp stub). Names are
    recorded only when resolution lands on a different function with a different
    name.
    """
    fm = program.getFunctionManager()
    listing = program.getListing()
    resolve_real_function = make_resolve_real_function(program)
    thunk_map: dict[str, str] = {}
    for tfn in fm.getFunctions(True):
        if not tfn.isThunk():
            ins = listing.getInstructionAt(tfn.getEntryPoint())
            if ins is None or ins.getMnemonicString().lower() != "jmp" or len(ins.getFlows()) != 1:
                continue
        resolved = resolve_real_function(tfn.getEntryPoint())
        if resolved is not None and resolved.getEntryPoint().getOffset() != tfn.getEntryPoint().getOffset():
            thunk_name = tfn.getName()  # bare thunk name
            real_name = resolved.getName(True)  # qualified with namespace
            if thunk_name != real_name:
                thunk_map[thunk_name] = real_name
    return thunk_map


def run(program, argv: list[str]) -> int:
    if not argv:
        print("usage: decompile 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2
    addrs = parse_addrs(argv)

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor

    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    ifc = DecompInterface()
    opts = DecompileOptions()
    ifc.setOptions(opts)
    ifc.setSimplificationStyle("decompile")
    if not ifc.openProgram(program):
        print(f"openProgram FAILED: {ifc.getLastMessage()}", file=sys.stderr)
        return 1
    mon = ConsoleTaskMonitor()

    try:
        resolve_real_function = make_resolve_real_function(program)
        # Build thunk-name -> real-name map for post-processing decompiled output.
        resolver = ThunkResolver(build_thunk_map(program))

        for addr_int in addrs:
            addr = af.getAddress(addr_int)
            fn = fm.getFunctionContaining(addr)
            resolved_fn = resolve_real_function(addr)
            if resolved_fn is not None and (fn is None or resolved_fn.getEntryPoint().getOffset() != fn.getEntryPoint().getOffset()):
                print(f"Resolving thunk 0x{addr_int:08x} -> actual function 0x{resolved_fn.getEntryPoint().getOffset():08x} ({resolved_fn.getName()})")
                fn = resolved_fn
                addr = fn.getEntryPoint()
                addr_int = int(addr.getOffset())

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
            print(resolver.resolve(res.getDecompiledFunction().getC()))
    finally:
        ifc.dispose()
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: decompile_one 0xADDR [0xADDR ...]", file=sys.stderr)
        return 2

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return run(program, sys.argv[1:])
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
