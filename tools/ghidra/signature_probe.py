#!/usr/bin/env python3
"""Read-only capture of DB function signatures + in_stack, for a fixed address list.

Diagnostic for the source->Ghidra *signature* projection gap (the 214 source-owned
functions whose DB signature is weaker than the C++ declaration). Run it before
and after ``just import-ghidra`` on the same addresses; diff the JSON to see what
the PDB import actually did per function.

Per address it records: calling convention, return type, formal params (name,
type, storage), varargs, custom-storage flag, and the current in_stack_* offsets
from a fresh decompile. Nothing is written to the DB.

  uv run python -m tools.ghidra.signature_probe --addrs 0x.. 0x.. --out probe.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.common import ghidra_env


def _decompiler(program):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.setSimplificationStyle("decompile")
    ifc.openProgram(program)
    return ifc


def _in_stack(hf):
    out = []
    it = hf.getLocalSymbolMap().getSymbols()
    while it.hasNext():
        s = it.next()
        if "in_stack_" not in s.getName() or s.isParameter():
            continue
        st = s.getStorage()
        if st.isStackStorage() and st.getStackOffset() > 0:
            dt = s.getDataType()
            out.append(f"0x{st.getStackOffset():x}:{dt.getLength() if dt else 0}")
    return sorted(out)


def capture(program, ifc, monitor, addr_int):
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fn = fm.getFunctionAt(af.getAddress(addr_int))
    if fn is None:
        return {"present": False}
    params = []
    for p in fn.getParameters():
        st = p.getVariableStorage()
        loc = f"stack@0x{st.getStackOffset():x}" if st.isStackStorage() else st.toString()
        dt = p.getDataType()
        params.append({"name": p.getName(),
                       "type": dt.getName() if dt else "?",
                       "size": dt.getLength() if dt else 0,
                       "storage": loc})
    ret = fn.getReturnType()
    rec = {
        "present": True,
        "name": fn.getName(True),
        "cc": fn.getCallingConventionName() or "",
        "return": ret.getName() if ret else "?",
        "varargs": fn.hasVarArgs(),
        "custom_storage": fn.hasCustomVariableStorage(),
        "nparams": len(params),
        "params": params,
        "purge": fn.getStackPurgeSize(),
    }
    res = ifc.decompileFunction(fn, 20, monitor)
    rec["in_stack"] = _in_stack(res.getHighFunction()) if (
        res.decompileCompleted() and res.getHighFunction() is not None) else ["<decomp-failed>"]
    return rec


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--addrs", nargs="+", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    import pyghidra

    project = ghidra_env.open_project()
    consumer = program = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=False)
        ifc = _decompiler(program)
        monitor = pyghidra.task_monitor()
        out = {}
        for a in args.addrs:
            ai = int(a, 16)
            out[f"0x{ai:08x}"] = capture(program, ifc, monitor, ai)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    Path(args.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(out)} functions)")
    for k, v in out.items():
        if not v.get("present"):
            print(f"  {k}: <absent>")
            continue
        ps = ",".join(f"{q['name']}:{q['type']}@{q['storage']}" for q in v["params"])
        print(f"  {k} {v['name']}: cc={v['cc']} ret={v['return']} "
              f"params=[{ps}] in_stack={v['in_stack']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
