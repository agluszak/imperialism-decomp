#!/usr/bin/env python3
"""Read-only pyghidra extractor: resolve vtable slots to real bodies as JSON.

The data half of the `just bootstrap-class` workflow. For one or more vtables it
reads each slot pointer, follows a single ILT `jmp` thunk to the real body, and
records the resolved target address, Ghidra name, size, listing signature and
(optionally) the decompiled C. Output is a JSON document the pure-python
`tools.workflow.bootstrap_class` codegen consumes, so the heavy Ghidra startup
runs once and the scaffolding logic stays Ghidra-free and unit-testable.

Usage:
  uv run python -m tools.ghidra.vtable_slots [--decompile] \
      Class=0x0066ee18[:COUNT] [Base=0x00653868[:COUNT] ...]

If :COUNT is omitted the extent is auto-detected — it stops at the next class's
vtable boundary (a slot-0 RTTI/classname getter), or at the first slot that is
neither a defined function, a thunk to one, nor null — and a warning is printed
to stderr advising you to verify it (trailing nulls before a boundary are
ambiguous: padding vs. abstract pure-virtual slots). JSON is written to stdout.
"""

from __future__ import annotations

import json
import sys

from tools.common import ghidra_env

MAX_SLOTS = 512


def is_rtti_getter(name: str | None) -> bool:
    """True if a slot target looks like a class's slot-0 classname/RTTI getter.

    The T-tree is MFC-rooted at CObject, where slot 0 of every class vtable is a
    ``GetRuntimeClass``-family getter (named ``Get<Class>ClassNamePointer`` here).
    Encountering one at slot index > 0 means we have run off the end of this
    vtable into the *next* class's table — a reliable auto-detect boundary.
    """
    if not name:
        return False
    return name == "GetRuntimeClass" or "ClassNamePointer" in name


def parse_spec(spec: str) -> tuple[str, int, int | None]:
    name, _, rhs = spec.partition("=")
    addr_s, _, count_s = rhs.partition(":")
    addr = int(addr_s, 16)
    count = int(count_s, 0) if count_s else None
    return name, addr, count


def main() -> int:
    argv = sys.argv[1:]
    decompile = False
    specs: list[str] = []
    for a in argv:
        if a in ("--decompile", "-d"):
            decompile = True
        else:
            specs.append(a)
    if not specs:
        print("usage: vtable_slots [--decompile] Name=0xVTABLE[:COUNT] ...", file=sys.stderr)
        return 2

    project = ghidra_env.open_project()
    consumer = None
    program = None
    ifc = None
    try:
        consumer, program = ghidra_env.open_program(project)
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()

        mon = None
        if decompile:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions
            from ghidra.util.task import ConsoleTaskMonitor

            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.setSimplificationStyle("decompile")
            ifc.openProgram(program)
            mon = ConsoleTaskMonitor()

        def resolve(entry: int) -> int:
            """Follow up to 8 single-flow JMP thunks to the real body address."""
            target = entry
            for _ in range(8):
                fn = fm.getFunctionContaining(af.getAddress(target))
                if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
                    break
                ins = listing.getInstructionAt(af.getAddress(target))
                if ins is None:
                    break
                if ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                    target = int(ins.getFlows()[0].getOffset())
                else:
                    break
            return target

        def slot_record(index: int, entry: int) -> dict:
            rec: dict = {
                "index": index,
                "byte_offset": index * 4,
                "slot_label": f"0x{index * 4:02x}",
                "entry_addr": f"0x{entry:08x}",
                "is_null": entry == 0,
            }
            if entry == 0:
                rec["target_addr"] = "0x00000000"
                return rec
            target = resolve(entry)
            rec["target_addr"] = f"0x{target:08x}"
            fn = fm.getFunctionContaining(af.getAddress(target))
            if fn is not None:
                rec["ghidra_name"] = fn.getName()
                rec["size"] = fn.getBody().getNumAddresses()
                rec["prototype"] = fn.getSignature(True).getPrototypeString()
                rec["calling_convention"] = fn.getCallingConventionName()
                if decompile and ifc is not None:
                    res = ifc.decompileFunction(fn, 60, mon)
                    if res.decompileCompleted():
                        rec["decompiled_c"] = res.getDecompiledFunction().getC()
            else:
                rec["ghidra_name"] = None
            return rec

        out: dict = {}
        for spec in specs:
            name, vtable, count = parse_spec(spec)
            slots: list[dict] = []
            limit = count if count is not None else MAX_SLOTS
            last_nonnull = -1  # index of the last resolvable (non-null) slot
            for i in range(limit):
                try:
                    entry = mem.getInt(af.getAddress(vtable + 4 * i)) & 0xFFFFFFFF
                except Exception:
                    break
                rec = slot_record(i, entry)
                if count is None and i > 0:
                    # Auto-detect boundary 1: the next class's vtable begins here
                    # (its slot-0 RTTI getter). Stop *before* it. This is the
                    # common case where two vtables abut with no gap.
                    if is_rtti_getter(rec.get("ghidra_name")):
                        trailing = i - 1 - last_nonnull
                        hint = (
                            f"; {trailing} trailing null slot(s) before it may be "
                            f"padding (likely real COUNT {last_nonnull + 1}) or abstract "
                            f"pure-virtual slots (COUNT {i}) — verify"
                            if trailing > 0
                            else ""
                        )
                        print(
                            f"[vtable_slots] {name}: stopped at slot 0x{i * 4:02x} — next "
                            f"vtable '{rec['ghidra_name']}' starts here{hint}; pass :COUNT "
                            f"to override.",
                            file=sys.stderr,
                        )
                        break
                    # Auto-detect boundary 2: a slot that is neither null nor a
                    # resolvable function body (likely the start of trailing data).
                    if not rec["is_null"] and rec.get("ghidra_name") is None:
                        print(
                            f"[vtable_slots] {name}: auto-detected {i} slots at 0x{vtable:08x} "
                            f"(stopped at unresolved 0x{entry:08x}); pass :COUNT to override.",
                            file=sys.stderr,
                        )
                        break
                if not rec["is_null"]:
                    last_nonnull = i
                slots.append(rec)
            out[name] = {"vtable_addr": f"0x{vtable:08x}", "slots": slots}

        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    finally:
        if ifc is not None:
            ifc.dispose()
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
