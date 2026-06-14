#!/usr/bin/env python3
"""One-off: ensure every TGreatPower vtable-slot body is a defined Ghidra function.

Resolves each vtable entry thunk (0x0040xxxx JMP) to its real body and runs
CreateFunctionCmd where no function exists yet, so the bodies can be decompiled and
paired by reccmp. Writable open + save. Run via:
  GHIDRA_INSTALL_DIR=... uv run python -m tools.ghidra.create_vtable_body_functions
"""
import csv, sys
import pyghidra

from tools.common import ghidra_env

VTABLE_CSV = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gp_vtable.csv"

project = ghidra_env.open_project()
from ghidra.app.cmd.function import CreateFunctionCmd
consumer, program = ghidra_env.open_program(project, writable=True)
df = program.getDomainFile()
try:
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()

    def resolve(a):
        cur = af.getAddress(a)
        for _ in range(6):
            ins = listing.getInstructionAt(cur)
            if ins is None:
                break
            f = ins.getFlows()
            if ins.getMnemonicString() == "JMP" and len(f) == 1:
                cur = f[0]
                continue
            break
        return cur

    rows = [r for r in csv.DictReader(open(VTABLE_CSV))
            if r["entry_addr"] and int(r["entry_addr"], 16) != 0]
    bodies = sorted({resolve(int(r["entry_addr"], 16)).getOffset() for r in rows})

    missing = [b for b in bodies if fm.getFunctionAt(af.getAddress(b)) is None]
    print(f"vtable bodies: {len(bodies)}  already-defined: {len(bodies)-len(missing)}  missing: {len(missing)}")

    txid = program.startTransaction("create vtable body functions")
    created, failed = [], []
    for b in missing:
        addr = af.getAddress(b)
        cmd = CreateFunctionCmd(addr)
        ok = cmd.applyTo(program, pyghidra.task_monitor())
        (created if ok and fm.getFunctionAt(addr) else failed).append(b)
    program.endTransaction(txid, True)

    print(f"created: {len(created)}  failed: {len(failed)}")
    for b in created:
        print(f"  +0x{b:08x}")
    if failed:
        print("FAILED:")
        for b in failed:
            print(f"  !0x{b:08x}")

    if created:
        df.save(pyghidra.task_monitor())
        print("saved program")
finally:
    program.release(consumer)
    project.close()
