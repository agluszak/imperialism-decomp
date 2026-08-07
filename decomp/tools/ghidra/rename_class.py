#!/usr/bin/env python3
"""Atomically re-attribute a class in the Ghidra DB (namespace + datatypes + vtable).

A class rename/reattribution is not an ordinary C++ rename: the same class shows up in
the Ghidra DB as a *function namespace*, a *class datatype*, a *vtable-structure
datatype*, and a *vtable label* — and `push_source_names` only touches function/label
names, so a datatype-level junk name (e.g. the retired ``TSoundChannelNode`` = source
``TLongintList`` behind vtable 0x650a08) survives every push. This command migrates all
four in one transaction, deriving the affected function addresses from the vtable and
the existing namespace rather than any class manifest.

  just ghidra-rename-class TSoundChannelNode TLongintList --vtable 0x650a08            # dry-run
  just ghidra-rename-class TSoundChannelNode TLongintList --vtable 0x650a08 --apply

What it does (only when a source of the OLD name actually exists):
  1. functions: every function in the OLD namespace -> moved to the NEW namespace
     (created if absent; if NEW already exists, functions merge into it).
  2. namespace: the emptied OLD class namespace is removed.
  3. datatypes: OLD -> NEW and OLD``Vtbl`` -> NEW``Vtbl`` (Ghidra rewrites every applied
     pointer/member reference automatically). If a NEW datatype already exists, the OLD
     one is replaced by it and removed.
  4. vtable label: the OLD ``::_vftable_`` symbol at --vtable is renamed under NEW.

Re-export (`just export-project`) and regenerate the autogen afterwards so
src/ghidra_autogen reflects the migration.
"""

from __future__ import annotations

import argparse

import pyghidra

from tools.common import ghidra_env


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("old", help="Current (junk) class name, e.g. TSoundChannelNode")
    p.add_argument("new", help="Correct source class name, e.g. TLongintList")
    p.add_argument("--vtable", required=True, help="Vtable address, e.g. 0x650a08")
    p.add_argument("--apply", action="store_true", help="Write and save the DB (default: dry-run).")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    vtable_addr = int(args.vtable, 16)
    project = ghidra_env.open_project()
    consumer = program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        from ghidra.program.model.symbol import SourceType

        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        g = program.getGlobalNamespace()
        af = program.getAddressFactory().getDefaultAddressSpace()

        old_ns = st.getNamespace(args.old, g)
        old_fns = [f for f in fm.getFunctions(True) if f.getParentNamespace() == old_ns] if old_ns else []
        old_dts = [dt for dt in dtm.getAllDataTypes() if dt.getName() in (args.old, args.old + "Vtbl")]
        vt = af.getAddress(vtable_addr)
        vt_syms = [s for s in st.getSymbols(vt) if args.old in s.getName(True)]

        print(f"OLD namespace {args.old!r}: exists={old_ns is not None} functions={len(old_fns)}")
        print(f"OLD datatypes: {[dt.getName() for dt in old_dts]}")
        print(f"vtable 0x{vtable_addr:x} OLD symbols: {[s.getName(True) for s in vt_syms]}")

        if old_ns is None and not old_dts and not vt_syms:
            print(f"Nothing to rename — {args.old!r} is not present in the DB.")
            return 0

        if not args.apply:
            print(f"[DRY RUN] would move {len(old_fns)} fn(s) -> {args.new}, "
                  f"rename {len(old_dts)} datatype(s), {len(vt_syms)} vtable symbol(s).")
            return 0

        txid = program.startTransaction(f"rename class {args.old}->{args.new}")
        new_ns = st.getNamespace(args.new, g)
        if new_ns is None:
            new_ns = st.createClass(g, args.new, SourceType.USER_DEFINED)

        # Set the vtable label under NEW *before* deleting the OLD namespace — the OLD
        # ``'vftable'`` symbol lives under the OLD namespace, so deleting that namespace
        # resets the label to a generic ``CObjectVtbl_*`` and any stale symbol handle
        # throws. createLabel+setPrimary is idempotent and covers rename and reset.
        renamed_sym = 0
        try:
            lbl = st.createLabel(vt, "'vftable'", new_ns, SourceType.USER_DEFINED)
            lbl.setPrimary()
            renamed_sym = 1
        except Exception as exc:  # noqa: BLE001
            print(f"  note: vtable label set failed: {exc}")

        moved = 0
        for f in old_fns:
            f.setParentNamespace(new_ns)
            moved += 1

        # Remove the now-empty OLD namespace symbol.
        if old_ns is not None and old_ns.getSymbol() is not None:
            try:
                old_ns.getSymbol().delete()
            except Exception as exc:  # noqa: BLE001 - report and continue
                print(f"  note: could not delete OLD namespace: {exc}")

        renamed_dt = 0
        for dt in old_dts:
            target = dt.getName().replace(args.old, args.new, 1)
            existing = next((d for d in dtm.getAllDataTypes()
                             if d.getName() == target and d.getPathName() != dt.getPathName()), None)
            try:
                if existing is not None:
                    dtm.replaceDataType(dt, existing, True)
                else:
                    dt.setName(target)
                renamed_dt += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  note: datatype {dt.getName()} -> {target} failed: {exc}")

        program.endTransaction(txid, True)
        txid = None
        program.save(f"rename class {args.old}->{args.new}", pyghidra.task_monitor())
        print(f"[APPLIED] moved_fn={moved} renamed_datatypes={renamed_dt} renamed_vtable_syms={renamed_sym}")
        print("Run `just export-project` and regenerate the autogen to converge src/ghidra_autogen.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
