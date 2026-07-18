#!/usr/bin/env python3
"""Read-only pyghidra extractor: resolve vtable slots to real bodies as JSON.

The data half of the `just recover-class` workflow. For one or more vtables it
reads each slot pointer, follows a single ILT `jmp` thunk to the real body, and
records the resolved target address, Ghidra name, size, listing signature and
(optionally) the decompiled C. Output is a JSON document the pure-python
`tools.workflow.class_codegen` codegen consumes, so the heavy Ghidra startup
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
from tools.workflow.vtable_extent_rules import extent_decision, is_rtti_getter

MAX_SLOTS = 512


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
        refmgr = program.getReferenceManager()

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
            """Resolve a vtable entry to its real (non-thunk) body address.

            The .text image opens with a dense incremental-link (ILT) table of
            5-byte `jmp <body>` stubs; Ghidra marks these as thunks. We never want
            to own/emit a thunk, so follow Ghidra's thunk chain first, then fall
            back to chasing raw single-flow JMPs (for stubs Ghidra didn't mark)."""
            target = entry
            for _ in range(8):
                addr = af.getAddress(target)
                fn = fm.getFunctionContaining(addr)
                # Ghidra-recognized thunk (ILT or otherwise) -> jump to real body.
                if fn is not None and fn.isThunk():
                    tf = fn.getThunkedFunction(True)
                    if tf is not None:
                        nxt = int(tf.getEntryPoint().getOffset())
                        if nxt == target:
                            break
                        target = nxt
                        continue
                if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
                    break
                ins = listing.getInstructionAt(addr)
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
                # True only if resolution could not escape a thunk (e.g. an
                # un-analyzed ILT stub); the generator must not own such a slot.
                rec["is_thunk"] = bool(fn.isThunk())
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

        IMG_LO, IMG_HI = 0x400000, 0x700000

        def in_image(a: int) -> bool:
            return IMG_LO <= a < IMG_HI

        def read_cstr(addr: int, limit: int = 64) -> str:
            bs = bytearray()
            for i in range(limit):
                try:
                    b = mem.getByte(af.getAddress(addr + i)) & 0xFF
                except Exception:
                    break
                if b == 0:
                    break
                bs.append(b)
            return bs.decode("latin1", "replace")

        def descriptor_from_getter(getter_entry: int) -> int | None:
            """The slot-0 RTTI getter is `mov eax, &CRuntimeClass; ret`; return the
            descriptor address it references."""
            fn = fm.getFunctionContaining(af.getAddress(getter_entry))
            if fn is None:
                return None
            it = listing.getInstructions(fn.getBody(), True)
            while it.hasNext():
                for ref in it.next().getReferencesFrom():
                    to = int(ref.getToAddress().getOffset())
                    if in_image(to) and ref.getReferenceType().isData():
                        return to
            return None

        def walk_ancestry(desc: int) -> list[dict]:
            """Follow MFC CRuntimeClass `m_pBaseClass` (+0x10), reading the class
            name (+0x00 -> char*) at each link, until the root (base == 0)."""
            chain: list[dict] = []
            seen: set[int] = set()
            cur = desc
            while cur and in_image(cur) and cur not in seen:
                seen.add(cur)
                try:
                    name = read_cstr(mem.getInt(af.getAddress(cur)) & 0xFFFFFFFF)
                    base = mem.getInt(af.getAddress(cur + 0x10)) & 0xFFFFFFFF
                except Exception:
                    break
                chain.append({"name": name, "descriptor": f"0x{cur:08x}"})
                if base == 0:
                    break
                cur = base
            return chain

        def descriptor_to_vtable(desc: int) -> int | None:
            """Find the vtable whose slot 0 dispatches to `desc`'s getter, via the
            reference graph (descriptor <- getter <- [ILT thunk] <- vtable slot0)."""
            for r in refmgr.getReferencesTo(af.getAddress(desc)):
                fn = fm.getFunctionContaining(r.getFromAddress())
                if fn is None:
                    continue
                getter = int(fn.getEntryPoint().getOffset())
                for r2 in refmgr.getReferencesTo(af.getAddress(getter)):
                    fa = int(r2.getFromAddress().getOffset())
                    ins = listing.getInstructionAt(af.getAddress(fa))
                    if ins is not None and ins.getMnemonicString().lower() == "jmp":
                        for r3 in refmgr.getReferencesTo(af.getAddress(fa)):
                            fa3 = int(r3.getFromAddress().getOffset())
                            if listing.getInstructionAt(af.getAddress(fa3)) is None:
                                return fa3  # data location == vtable slot 0
                    elif ins is None:
                        return fa  # direct (un-thunked) vtable slot 0
            return None

        def resolve_rtti(class_slots: list[dict]) -> dict | None:
            """From a class's slot 0, recover its name, full ancestry, the
            CObject-vs-TObject root branch, and the immediate base + its vtable."""
            if not class_slots or class_slots[0].get("is_null"):
                return None
            getter = int(class_slots[0]["target_addr"], 16)
            desc = descriptor_from_getter(getter)
            if desc is None:
                return None
            chain = walk_ancestry(desc)
            if not chain:
                return None
            names = [c["name"] for c in chain]
            rtti: dict = {
                "class_name": names[0],
                "ancestry": names,
                # CObject is the absolute root; a TObject in the chain marks the
                # game-object branch, otherwise it is a direct-CObject (MFC) class.
                "root": "TObject" if "TObject" in names[1:] else "CObject",
            }
            if len(chain) > 1:
                rtti["immediate_base"] = names[1]
                base_desc = int(chain[1]["descriptor"], 16)
                base_vt = descriptor_to_vtable(base_desc)
                if base_vt is not None:
                    rtti["immediate_base_vtable"] = f"0x{base_vt:08x}"
            return rtti

        def extract(name: str, vtable: int, count: int | None) -> dict:
            slots: list[dict] = []
            limit = count if count is not None else MAX_SLOTS
            last_nonnull = -1  # index of the last resolvable (non-null) slot
            null_run_seen = False
            for i in range(limit):
                try:
                    entry = mem.getInt(af.getAddress(vtable + 4 * i)) & 0xFFFFFFFF
                except Exception:
                    break
                rec = slot_record(i, entry)
                if count is None:
                    decision = extent_decision(
                        i, bool(rec["is_null"]), rec.get("ghidra_name"), null_run_seen
                    )
                    if decision.stop:
                        if decision.reason == "rtti_getter":
                            # Boundary 1: the next class's vtable begins here (its
                            # slot-0 RTTI getter). Stop *before* it. This is the
                            # common case where two vtables abut with no gap.
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
                        elif decision.reason == "unresolved":
                            # Boundary 2: a slot that is neither null nor a
                            # resolvable function body (likely the start of trailing data).
                            print(
                                f"[vtable_slots] {name}: auto-detected {i} slots at 0x{vtable:08x} "
                                f"(stopped at unresolved 0x{entry:08x}); pass :COUNT to override.",
                                file=sys.stderr,
                            )
                        else:
                            # Boundary 3: function pointers resuming after a null run
                            # usually belong to an ADJACENT non-RTTI table (stretch<T>
                            # and other template tables have no slot-0 getter, so
                            # boundary 1 cannot see them — the TMapMaker incident).
                            # Resuming the table requires an explicit reviewed :COUNT.
                            print(
                                f"[vtable_slots] {name}: stopped at slot 0x{i * 4:02x} — "
                                f"function pointers resume after {i - 1 - last_nonnull} "
                                f"null slot(s); the resumed entries likely belong to an "
                                f"adjacent non-RTTI/template vtable. Auto-extent kept "
                                f"COUNT {i}; pass :COUNT to override after review.",
                                file=sys.stderr,
                            )
                        break
                if not rec["is_null"]:
                    last_nonnull = i
                else:
                    null_run_seen = True
                slots.append(rec)
            return {"vtable_addr": f"0x{vtable:08x}", "slots": slots}

        out: dict = {}
        parsed = [parse_spec(s) for s in specs]
        for name, vtable, count in parsed:
            out[name] = extract(name, vtable, count)

        # Recover the inheritance edge of the first (class) spec from its MFC
        # CRuntimeClass chain, and — when no base was supplied — auto-extract the
        # immediate base's vtable so the codegen can diff inherited vs. override.
        class_name = parsed[0][0]
        rtti = resolve_rtti(out[class_name]["slots"])
        if rtti is not None:
            out[class_name]["rtti"] = rtti
            chain_str = " -> ".join(rtti["ancestry"])
            print(
                f"[vtable_slots] {class_name}: {rtti['root']}-branch; ancestry {chain_str}",
                file=sys.stderr,
            )
            base = rtti.get("immediate_base")
            base_vt = rtti.get("immediate_base_vtable")
            if base and base not in out:
                if base_vt:
                    out[base] = extract(base, int(base_vt, 16), None)
                    print(
                        f"[vtable_slots] auto-extracted base {base} @ {base_vt} "
                        f"(from RTTI; pass it explicitly to override).",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"[vtable_slots] {class_name}: immediate base {base} found via RTTI "
                        "but its vtable could not be located; pass it explicitly.",
                        file=sys.stderr,
                    )

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
