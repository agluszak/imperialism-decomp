#!/usr/bin/env python3
"""Probe likely class ownership for a function address in the vendored Ghidra project.

Usage:
  just class-owner-probe 0x00583bd0
  uv run python -m tools.ghidra.class_owner_probe 0x00583bd0 --context 12

Reports:
- whether Ghidra has a function at/containing the target address;
- nearby listing if it does not;
- direct refs and thunk/JMP aliases;
- vtable/data-pointer refs to the target;
- refs to candidate vtable bases, usually constructors/vptr writes;
- caller context, especially ECX setup before CALL;
- this-like field offsets and indirect calls inside the target body.

This script is read-only.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeAlias, cast

from tools.common import ghidra_env

if TYPE_CHECKING:
    from ghidra.framework.model import DomainFile, DomainObject, Project
    from ghidra.program.model.address import Address, AddressFactory, AddressSpace
    from ghidra.program.model.listing import Data, Function, FunctionManager, Instruction, Listing, Program
    from ghidra.program.model.symbol import Reference, ReferenceManager, Symbol, SymbolTable
else:
    Address: TypeAlias = Any
    AddressFactory: TypeAlias = Any
    AddressSpace: TypeAlias = Any
    Data: TypeAlias = Any
    DomainFile: TypeAlias = Any
    DomainObject: TypeAlias = Any
    Function: TypeAlias = Any
    FunctionManager: TypeAlias = Any
    Instruction: TypeAlias = Any
    Listing: TypeAlias = Any
    Program: TypeAlias = Any
    Project: TypeAlias = Any
    Reference: TypeAlias = Any
    ReferenceManager: TypeAlias = Any
    Symbol: TypeAlias = Any
    SymbolTable: TypeAlias = Any


THIS_MEM_RE = re.compile(r"\[(E(?:AX|BX|CX|DX|SI|DI|BP|SP))(?: \+ (0x[0-9a-fA-F]+))?\]")
VTABLE_CALL_RE = re.compile(r"CALL dword ptr \[(E[A-Z]{2}) \+ (0x[0-9a-fA-F]+)\]")


@dataclass(frozen=True)
class VtableRef:
    entry_addr: Address
    base_addr: Address
    base_symbol: str
    byte_offset: int
    slot_index: int | None
    entry_symbol: str
    ref_type: str
    data_repr: str


def iter_java_maybe(value: Any) -> Iterator[Any]:
    """Handle Java iterators, Java arrays, Python sequences, and singletons."""
    if value is None:
        return

    if hasattr(value, "hasNext") and hasattr(value, "next"):
        while value.hasNext():
            yield value.next()
        return

    try:
        iterator = iter(value)
    except TypeError:
        yield value
        return

    yield from iterator


def parse_int(value: str) -> int:
    value = value.strip()
    return int(value, 16) if value.lower().startswith("0x") else int(value, 16)


def is_memory_addr(addr: Address | None) -> bool:
    if addr is None:
        return False
    try:
        return bool(addr.isMemoryAddress())
    except Exception:
        return False


def is_external_addr(addr: Address | None) -> bool:
    if addr is None:
        return False
    try:
        return bool(addr.isExternalAddress())
    except Exception:
        return False


def addr_to_int(addr: Address) -> int:
    """Return memory address offset. Reject EXTERNAL/REGISTER/STACK/etc. addresses."""
    if not is_memory_addr(addr):
        raise ValueError(f"not a memory address: {addr}")
    return int(addr.getOffset())


def addr_sort_key(addr: Address) -> tuple[int, str, int]:
    """Stable sort key that tolerates EXTERNAL addresses."""
    try:
        space_name = str(addr.getAddressSpace().getName())
    except Exception:
        space_name = ""
    try:
        offset = int(addr.getOffset())
    except Exception:
        offset = 0
    return (0 if is_memory_addr(addr) else 1, space_name, offset)


def fmt_addr(addr: Address | None) -> str:
    if addr is None:
        return "<none>"

    if is_memory_addr(addr):
        return f"0x{int(addr.getOffset()):08x}"

    try:
        return addr.toString(True)
    except Exception:
        return str(addr)


def same_memory_addr(a: Address | None, b: Address | None) -> bool:
    if not is_memory_addr(a) or not is_memory_addr(b):
        return False
    return int(a.getOffset()) == int(b.getOffset()) and a.hasSameAddressSpace(b)


def get_default_space(program: Program) -> AddressSpace:
    return cast(AddressSpace, program.getAddressFactory().getDefaultAddressSpace())


def addr_from_int(program: Program, value: int) -> Address:
    return cast(Address, get_default_space(program).getAddress(value))


def get_symbol_names_at(program: Program, addr: Address) -> list[str]:
    out: list[str] = []
    symtab = cast(SymbolTable, program.getSymbolTable())
    for sym_raw in iter_java_maybe(symtab.getSymbols(addr)):
        sym = cast(Symbol, sym_raw)
        out.append(str(sym.getName(True)))
    return out


def get_primary_symbol_name(program: Program, addr: Address) -> str:
    names = get_symbol_names_at(program, addr)
    return names[0] if names else ""


def get_function_containing(program: Program, addr: Address) -> Function | None:
    return cast(Function | None, program.getFunctionManager().getFunctionContaining(addr))


def get_function_name(program: Program, addr: Address) -> str:
    fn = get_function_containing(program, addr)
    return str(fn.getName(True)) if fn is not None else ""


def flows_of(ins: Instruction) -> list[Address]:
    return [cast(Address, flow) for flow in iter_java_maybe(ins.getFlows())]


def function_at_or_containing(program: Program, addr: Address) -> Function | None:
    fm = cast(FunctionManager, program.getFunctionManager())
    listing = cast(Listing, program.getListing())

    fn = cast(Function | None, fm.getFunctionContaining(addr))
    if fn is not None:
        return fn

    ins = cast(Instruction | None, listing.getInstructionAt(addr))
    if ins is None:
        return None

    if str(ins.getMnemonicString()).upper() == "JMP":
        memory_flows = [flow for flow in flows_of(ins) if is_memory_addr(flow)]
        if len(memory_flows) == 1:
            return cast(Function | None, fm.getFunctionContaining(memory_flows[0]))

    return None


def prev_instructions(listing: Listing, addr: Address, count: int) -> list[Instruction]:
    out: list[Instruction] = []
    ins = cast(Instruction | None, listing.getInstructionBefore(addr))
    while ins is not None and len(out) < count:
        out.append(ins)
        ins = cast(Instruction | None, listing.getInstructionBefore(ins.getAddress()))
    out.reverse()
    return out


def print_listing_context(program: Program, addr: Address, before: int = 10, after: int = 28) -> None:
    listing = cast(Listing, program.getListing())
    print("listing context:")

    ins = cast(Instruction | None, listing.getInstructionAt(addr))
    if ins is None:
        ins = cast(Instruction | None, listing.getInstructionAfter(addr))

    if ins is None:
        print("  no instruction at or after target")
        return

    start = ins
    for _ in range(before):
        prev = cast(Instruction | None, listing.getInstructionBefore(start.getAddress()))
        if prev is None:
            break
        start = prev

    cur: Instruction | None = start
    count = 0

    while cur is not None and count < before + after:
        marker = "*" if same_memory_addr(cur.getAddress(), addr) else " "
        print(f" {marker} {fmt_addr(cur.getAddress())}: {cur}")
        cur = cast(Instruction | None, listing.getInstructionAfter(cur.getAddress()))
        count += 1


def print_function_summary(program: Program, target_addr: Address) -> Function | None:
    fn = function_at_or_containing(program, target_addr)
    print("=" * 80)

    if fn is None:
        print(f"target,{fmt_addr(target_addr)},no function")
        return None

    print(
        f"target,{fmt_addr(target_addr)},"
        f"function={fmt_addr(fn.getEntryPoint())},"
        f"name={fn.getName(True)},"
        f"signature={fn.getSignature()}"
    )
    return fn


def collect_direct_or_thunk_targets(program: Program, target_addr: Address) -> list[Address]:
    """Return raw target plus small memory JMP thunks that jump to it."""
    listing = cast(Listing, program.getListing())
    fm = cast(FunctionManager, program.getFunctionManager())
    refman = cast(ReferenceManager, program.getReferenceManager())

    targets: dict[tuple[int, str, int], Address] = {addr_sort_key(target_addr): target_addr}

    funcs = fm.getFunctions(True)
    while funcs.hasNext():
        fn = cast(Function, funcs.next())
        entry = cast(Address, fn.getEntryPoint())

        if fn.getBody().getNumAddresses() > 32:
            continue

        ins = cast(Instruction | None, listing.getInstructionAt(entry))
        if ins is None:
            continue

        if str(ins.getMnemonicString()).upper() != "JMP":
            continue

        memory_flows = [flow for flow in flows_of(ins) if is_memory_addr(flow)]
        if len(memory_flows) == 1 and same_memory_addr(memory_flows[0], target_addr):
            targets[addr_sort_key(entry)] = entry

    for ref_raw in iter_java_maybe(refman.getReferencesTo(target_addr)):
        ref = cast(Reference, ref_raw)
        from_addr = cast(Address, ref.getFromAddress())
        ins = cast(Instruction | None, listing.getInstructionAt(from_addr))
        if ins is not None and str(ins.getMnemonicString()).upper() == "JMP":
            targets[addr_sort_key(from_addr)] = from_addr

    return [targets[key] for key in sorted(targets.keys())]


def print_direct_targets(program: Program, target_addrs: Sequence[Address]) -> None:
    print("direct/thunk targets:")
    if not target_addrs:
        print("  none")
        return

    for addr in target_addrs:
        fn_name = get_function_name(program, addr) or "-"
        sym_name = get_primary_symbol_name(program, addr) or "-"
        print(f"  {fmt_addr(addr)} function={fn_name} symbol={sym_name}")


def find_pointer_refs_to_target(program: Program, target_addr: Address) -> list[tuple[Address, str, str, str]]:
    """Find data refs that look like vtable/data pointer entries pointing at target."""
    refman = cast(ReferenceManager, program.getReferenceManager())
    fm = cast(FunctionManager, program.getFunctionManager())
    listing = cast(Listing, program.getListing())

    rows: list[tuple[Address, str, str, str]] = []

    for ref_raw in iter_java_maybe(refman.getReferencesTo(target_addr)):
        ref = cast(Reference, ref_raw)
        from_addr = cast(Address, ref.getFromAddress())

        from_fn = cast(Function | None, fm.getFunctionContaining(from_addr))
        if from_fn is not None:
            continue

        data = cast(Data | None, listing.getDataAt(from_addr))
        rows.append(
            (
                from_addr,
                get_primary_symbol_name(program, from_addr),
                str(data) if data is not None else "",
                str(ref.getReferenceType()),
            )
        )

    return rows


def guess_vtable_base(program: Program, entry_addr: Address, max_back_entries: int = 256) -> tuple[Address, str, int, int | None]:
    """Heuristic vtable base: nearest named memory address backwards, else start of data run."""
    listing = cast(Listing, program.getListing())
    entry_offset = addr_to_int(entry_addr)

    for step in range(0, max_back_entries + 1):
        candidate = addr_from_int(program, entry_offset - step * 4)
        names = get_symbol_names_at(program, candidate)
        if names:
            byte_offset = entry_offset - addr_to_int(candidate)
            slot_index = byte_offset // 4 if byte_offset >= 0 else None
            return candidate, names[0], byte_offset, slot_index

    base = entry_addr
    for step in range(1, max_back_entries + 1):
        candidate = addr_from_int(program, entry_offset - step * 4)
        data = cast(Data | None, listing.getDataAt(candidate))
        if data is None:
            break
        base = candidate

    byte_offset = entry_offset - addr_to_int(base)
    slot_index = byte_offset // 4 if byte_offset >= 0 else None
    return base, "", byte_offset, slot_index


def collect_vtable_evidence(program: Program, target_addr: Address) -> list[VtableRef]:
    rows = find_pointer_refs_to_target(program, target_addr)
    out: list[VtableRef] = []

    for entry_addr, entry_symbol, data_repr, ref_type in rows:
        if not is_memory_addr(entry_addr):
            continue

        base, base_sym, byte_off, slot_idx = guess_vtable_base(program, entry_addr)
        out.append(
            VtableRef(
                entry_addr=entry_addr,
                base_addr=base,
                base_symbol=base_sym,
                byte_offset=byte_off,
                slot_index=slot_idx,
                entry_symbol=entry_symbol,
                ref_type=ref_type,
                data_repr=data_repr,
            )
        )

    return out


def print_vtable_evidence(program: Program, target_addr: Address) -> list[VtableRef]:
    rows = collect_vtable_evidence(program, target_addr)

    print("vtable/data-pointer refs to target:")
    if not rows:
        print("  none")
        return []

    for row in rows:
        print(
            "  "
            f"entry={fmt_addr(row.entry_addr)} "
            f"base={fmt_addr(row.base_addr)} "
            f"slot={row.slot_index if row.slot_index is not None else '-'} "
            f"byte_off=0x{row.byte_offset:x} "
            f"base_sym={row.base_symbol or '-'} "
            f"entry_sym={row.entry_symbol or '-'} "
            f"ref_type={row.ref_type} "
            f"data={row.data_repr or '-'}"
        )

    return rows


def print_vtable_base_refs(program: Program, vtable_rows: Sequence[VtableRef], max_refs_per_vtable: int = 30) -> None:
    refman = cast(ReferenceManager, program.getReferenceManager())
    fm = cast(FunctionManager, program.getFunctionManager())

    unique_bases: list[Address] = []
    seen: set[tuple[int, str, int]] = set()

    for row in vtable_rows:
        key = addr_sort_key(row.base_addr)
        if key in seen:
            continue
        seen.add(key)
        unique_bases.append(row.base_addr)

    print("refs to candidate vtable bases:")
    if not unique_bases:
        print("  none")
        return

    for base in unique_bases:
        print(f"  vtable={fmt_addr(base)} symbol={get_primary_symbol_name(program, base) or '-'}")
        refs = list(iter_java_maybe(refman.getReferencesTo(base)))

        if not refs:
            print("    no refs")
            continue

        for ref_raw in refs[:max_refs_per_vtable]:
            ref = cast(Reference, ref_raw)
            from_addr = cast(Address, ref.getFromAddress())
            fn = cast(Function | None, fm.getFunctionContaining(from_addr))
            fn_name = str(fn.getName(True)) if fn is not None else "-"
            print(f"    {fmt_addr(from_addr)} in {fn_name} ref_type={ref.getReferenceType()}")


def print_callsite_context(program: Program, target_addrs: Sequence[Address], context: int) -> None:
    listing = cast(Listing, program.getListing())
    fm = cast(FunctionManager, program.getFunctionManager())
    refman = cast(ReferenceManager, program.getReferenceManager())

    print("callers / callsite context:")
    printed: set[tuple[tuple[int, str, int], tuple[int, str, int]]] = set()
    found = False

    for target in target_addrs:
        for ref_raw in iter_java_maybe(refman.getReferencesTo(target)):
            ref = cast(Reference, ref_raw)
            from_addr = cast(Address, ref.getFromAddress())
            ins = cast(Instruction | None, listing.getInstructionAt(from_addr))
            if ins is None:
                continue

            mnemonic = str(ins.getMnemonicString()).upper()
            if mnemonic not in {"CALL", "JMP"}:
                continue

            key = (addr_sort_key(from_addr), addr_sort_key(target))
            if key in printed:
                continue

            printed.add(key)
            found = True

            caller = cast(Function | None, fm.getFunctionContaining(from_addr))
            caller_name = str(caller.getName(True)) if caller is not None else "-"
            print(f"  callsite={fmt_addr(from_addr)} target={fmt_addr(target)} caller={caller_name}")

            for prev in prev_instructions(listing, from_addr, context):
                text = str(prev)
                marker = "  > " if "ECX" in text.upper() else "    "
                print(f"{marker}{fmt_addr(prev.getAddress())}: {text}")

            print(f"  * {fmt_addr(ins.getAddress())}: {ins}")

            after = cast(Instruction | None, listing.getInstructionAfter(ins.getAddress()))
            if after is not None:
                print(f"    {fmt_addr(after.getAddress())}: {after}")

    if not found:
        print("  none")


def print_target_body_this_offsets(program: Program, fn: Function | None) -> None:
    listing = cast(Listing, program.getListing())

    print("target body this/field evidence:")
    if fn is None:
        print("  no function, create one in Ghidra or fix analysis first")
        return

    indirect_calls: list[tuple[Address, str, str, str]] = []
    memory_refs: list[tuple[Address, str, str, str]] = []

    for ins_raw in iter_java_maybe(listing.getInstructions(fn.getBody(), True)):
        ins = cast(Instruction, ins_raw)
        text = str(ins)
        mnemonic = str(ins.getMnemonicString()).upper()

        if mnemonic == "CALL":
            match = VTABLE_CALL_RE.search(text)
            if match:
                indirect_calls.append((ins.getAddress(), match.group(1), match.group(2), text))

        for match in THIS_MEM_RE.finditer(text):
            reg = match.group(1)
            off = match.group(2) or "0x0"
            memory_refs.append((ins.getAddress(), reg, off, text))

    print("  indirect calls:")
    if not indirect_calls:
        print("    none")
    for addr, reg, off, text in indirect_calls:
        print(f"    {fmt_addr(addr)} reg={reg} off={off} text={text}")

    print("  memory refs:")
    if not memory_refs:
        print("    none")

    seen: set[tuple[str, str, str]] = set()
    for addr, reg, off, text in memory_refs:
        key = (reg, off, text)
        if key in seen:
            continue
        seen.add(key)
        marker = "likely_this" if reg in {"ECX", "ESI", "EDI"} else "mem"
        print(f"    {fmt_addr(addr)} {marker} reg={reg} off={off} text={text}")


def print_function_metadata(fn: Function | None) -> None:
    print("function metadata:")
    if fn is None:
        print("  no function")
        return

    print(f"  name: {fn.getName(True)}")
    print(f"  entry: {fmt_addr(fn.getEntryPoint())}")
    print(f"  signature: {fn.getSignature()}")
    print(f"  calling convention: {fn.getCallingConventionName()}")
    print(f"  comment: {fn.getComment() or '-'}")
    print(f"  repeatable comment: {fn.getRepeatableComment() or '-'}")


def load_program(project: Project):
    consumer, program = ghidra_env.open_program(project)
    return consumer, cast(Program, program)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("address", help="Target memory address, e.g. 0x00583bd0")
    parser.add_argument("--context", type=int, default=10, help="instructions before callsite")
    parser.add_argument("--listing-before", type=int, default=10)
    parser.add_argument("--listing-after", type=int, default=28)
    args = parser.parse_args()

    project = cast(Project, ghidra_env.open_project())

    consumer: Any | None = None
    program: Program | None = None

    try:
        consumer, program = load_program(project)
        target_addr = addr_from_int(program, parse_int(args.address))

        fn = print_function_summary(program, target_addr)
        print_function_metadata(fn)

        if fn is None:
            print_listing_context(program, target_addr, args.listing_before, args.listing_after)

        target_addrs = collect_direct_or_thunk_targets(program, target_addr)
        print_direct_targets(program, target_addrs)

        vtable_rows = print_vtable_evidence(program, target_addr)
        print_vtable_base_refs(program, vtable_rows)

        print_callsite_context(program, target_addrs, args.context)
        print_target_body_this_offsets(program, fn)

    finally:
        if program is not None and consumer is not None:
            program.release(consumer)
        project.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())