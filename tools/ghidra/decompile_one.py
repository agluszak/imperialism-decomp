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
                    ins = program.getListing().getInstructionAt(fn.getEntryPoint())
                    if ins is not None and ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                        curr = ins.getFlows()[0]
                        continue
                    return fn
                ins = program.getListing().getInstructionAt(curr)
                if ins is not None and ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                    curr = ins.getFlows()[0]
                    continue
                break
            return fm.getFunctionContaining(curr)

        # Build thunk-name -> real-name map for post-processing decompiled output
        import re as _re
        _thunk_map: dict[str, str] = {}
        for tfn in fm.getFunctions(True):
            if not tfn.isThunk():
                ins = program.getListing().getInstructionAt(tfn.getEntryPoint())
                if ins is None or ins.getMnemonicString().lower() != "jmp" or len(ins.getFlows()) != 1:
                    continue
            resolved = resolve_real_function(tfn.getEntryPoint())
            if resolved is not None and resolved.getEntryPoint().getOffset() != tfn.getEntryPoint().getOffset():
                thunk_name = tfn.getName()  # bare thunk name
                real_name = resolved.getName(True)  # qualified with namespace
                if thunk_name != real_name:
                    _thunk_map[thunk_name] = real_name
        # Two name families need different handling to avoid corrupting the output:
        #  * "thunk_*" names are genuine Ghidra thunk auto-names that only ever appear as
        #    thunk calls. The decompiler may print them qualified by the target's class
        #    (e.g. "TCity::thunk_Foo"); we consume any leading namespace qualifier(s) and
        #    rewrite the whole token to the authoritative real name "TCity::Foo".
        #  * other names come from jmp-stub aliases whose name equals the target's bare
        #    name and thus collide with real symbols (headers, already-correct qualified
        #    calls, and even type names -- a constructor's simple name like "TGreatPower"
        #    maps to "TGreatPower::TGreatPower"). We only rewrite these when unqualified
        #    AND in call position (followed by "("), so we never double-qualify nor
        #    corrupt a type cast / declaration that merely shares the bare name.
        _thunk_alts = sorted(
            (_re.escape(k) for k in _thunk_map if k.startswith("thunk_")), key=len, reverse=True
        )
        _other_alts = sorted(
            (_re.escape(k) for k in _thunk_map if not k.startswith("thunk_")), key=len, reverse=True
        )
        _branches = []
        if _thunk_alts:
            _branches.append(r'(?:[A-Za-z_]\w*::)*(' + '|'.join(_thunk_alts) + r')')
        if _other_alts:
            _branches.append(r'(' + '|'.join(_other_alts) + r')(?=\s*\()')
        if _branches:
            _thunk_re = _re.compile(r'(?<![:\w])(?:' + '|'.join(_branches) + r')\b')
        else:
            _thunk_re = None

        def resolve_thunks_in_source(c_text: str) -> str:
            if _thunk_re is None:
                return c_text
            return _thunk_re.sub(
                lambda m: _thunk_map[next(g for g in m.groups() if g is not None)], c_text
            )

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
            print(resolve_thunks_in_source(res.getDecompiledFunction().getC()))
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
