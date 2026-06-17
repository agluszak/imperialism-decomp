#!/usr/bin/env python3
"""Suggest vtable_slot_method_overrides.csv rows from header VTABLE addresses.

Resolves each slot through Ghidra (ILT thunk chain), maps body addresses to
owned symbol names, and emits reviewable CSV suggestions.

Usage:
  uv run python -m tools.ghidra.gen_vtable_slot_overrides
  uv run python -m tools.ghidra.gen_vtable_slot_overrides --class TSimMgr
  uv run python -m tools.ghidra.gen_vtable_slot_overrides --write
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file

REPO = repo_root_from_file(__file__)
INCLUDE_GAME = REPO / "include" / "game"
OUT_PATH = REPO / "config" / "vtable_slot_method_overrides.generated.csv"
SYMBOLS_PATH = REPO / "config" / "symbols.csv"
MAC_SYMBOLS_PATH = REPO / "vendor" / "macos_codewarrior" / "evidence" / "symbols.csv"
ALIASES_PATH = REPO / "config" / "class_vtable_aliases.csv"
CURATED_PATH = REPO / "config" / "vtable_slot_method_overrides.csv"

VTABLE_HEADER = re.compile(
    r"^\s*//\s*VTABLE:\s*IMPERIALISM\s+(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
CLASS_DECL = re.compile(r"^\s*class\s+(\w+)")


@dataclass(frozen=True)
class VtableSpec:
    class_name: str
    vtable_addr: int
    header: str


@dataclass(frozen=True)
class SlotSuggestion:
    class_name: str
    slot_index: int
    method_name: str
    mac_method: str
    note: str

    def to_row(self) -> dict[str, str]:
        return {
            "class": self.class_name,
            "slot_index": f"0x{self.slot_index:x}",
            "method_name": self.method_name,
            "mac_method": self.mac_method,
            "note": self.note,
        }


def discover_vtable_specs(class_filter: str | None = None) -> list[VtableSpec]:
    specs: list[VtableSpec] = []
    for path in sorted(INCLUDE_GAME.glob("*.h")):
        pending_vt: int | None = None
        for line in path.read_text(encoding="utf-8").splitlines():
            vt_match = VTABLE_HEADER.match(line)
            if vt_match:
                pending_vt = int(vt_match.group(1), 16)
                continue
            class_match = CLASS_DECL.match(line)
            if not class_match:
                continue
            class_name = class_match.group(1)
            if pending_vt is not None:
                if class_filter is None or class_name == class_filter:
                    specs.append(VtableSpec(class_name, pending_vt, path.name))
                pending_vt = None
    return specs


def load_symbol_names() -> dict[int, str]:
    names: dict[int, str] = {}
    if not SYMBOLS_PATH.exists():
        return names
    for row in read_pipe_rows(SYMBOLS_PATH):
        addr_s = (row.get("address") or "").strip()
        name = (row.get("name") or "").strip()
        if not addr_s or not name:
            continue
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        if "::" in name:
            name = name.split("::", 1)[1]
        if name.startswith("thunk_"):
            continue
        names[addr] = name
    return names


def load_mac_methods() -> dict[tuple[str, str], str]:
    methods: dict[tuple[str, str], str] = {}
    if not MAC_SYMBOLS_PATH.exists():
        return methods
    with MAC_SYMBOLS_PATH.open(encoding="utf-8") as fd:
        for row in csv.DictReader(fd):
            owner = (row.get("owner") or "").strip()
            method = (row.get("method") or "").strip()
            confidence = (row.get("confidence") or "").strip()
            if owner and method and confidence == "high":
                methods[(owner, method)] = method
    return methods


def load_curated_keys() -> set[tuple[str, int]]:
    keys: set[tuple[str, int]] = set()
    for row in read_pipe_rows(CURATED_PATH):
        cls = (row.get("class") or "").strip()
        slot_s = (row.get("slot_index") or "").strip()
        if not cls or not slot_s:
            continue
        slot = int(slot_s, 16) if slot_s.lower().startswith("0x") else int(slot_s)
        keys.add((cls, slot))
    return keys


def load_alias_map() -> dict[str, str]:
    aliases: dict[str, str] = {}
    for row in read_pipe_rows(ALIASES_PATH):
        alias = (row.get("alias_class") or "").strip()
        canonical = (row.get("canonical_class") or "").strip()
        if alias and canonical:
            aliases[alias] = canonical
    return aliases


def ghidra_read_slots(vtable_addr: int, max_slots: int = 200) -> list[tuple[int, int | None, str | None]]:
    from tools.common import ghidra_env

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()

        def resolve(entry: int) -> tuple[int, str | None]:
            target = entry
            for _ in range(8):
                addr = af.getAddress(target)
                fn = fm.getFunctionContaining(addr)
                if fn is not None and fn.isThunk():
                    tf = fn.getThunkedFunction(True)
                    if tf is not None:
                        nxt = int(tf.getEntryPoint().getOffset())
                        if nxt == target:
                            break
                        target = nxt
                        continue
                if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
                    return target, fn.getName()
                ins = listing.getInstructionAt(addr)
                if ins is None:
                    break
                if ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                    target = int(ins.getFlows()[0].getOffset())
                else:
                    break
            fn = fm.getFunctionContaining(af.getAddress(target))
            return target, fn.getName() if fn is not None else None

        slots: list[tuple[int, int | None, str | None]] = []
        for index in range(max_slots):
            off = vtable_addr + index * 4
            try:
                entry = mem.getInt(af.getAddress(off)) & 0xFFFFFFFF
            except Exception:  # noqa: BLE001
                break
            if entry == 0:
                slots.append((index, None, None))
                continue
            target, name = resolve(entry)
            slots.append((index, target, name))
            if index > 0 and entry == mem.getInt(af.getAddress(vtable_addr)) & 0xFFFFFFFF:
                slots.pop()
                break
        return slots
    finally:
        if program is not None and consumer is not None:
            program.release(consumer)
        project.close()


def suggest_method_name(target: int, symbol_names: dict[int, str], ghidra_name: str | None) -> str | None:
    if target in symbol_names:
        return symbol_names[target]
    if ghidra_name and not ghidra_name.startswith("FUN_") and "VtblSlot" not in ghidra_name:
        if "::" in ghidra_name:
            return ghidra_name.split("::", 1)[1]
        return ghidra_name
    return None


def build_suggestions(specs: list[VtableSpec]) -> list[SlotSuggestion]:
    symbol_names = load_symbol_names()
    mac_methods = load_mac_methods()
    curated = load_curated_keys()
    aliases = load_alias_map()
    suggestions: list[SlotSuggestion] = []

    for spec in specs:
        lookup_class = aliases.get(spec.class_name, spec.class_name)
        try:
            slots = ghidra_read_slots(spec.vtable_addr)
        except Exception as exc:  # noqa: BLE001
            print(f"skip {spec.class_name}: {exc}", file=sys.stderr)
            continue
        for index, target, ghidra_name in slots:
            if target is None:
                continue
            if (lookup_class, index) in curated or (spec.class_name, index) in curated:
                continue
            method = suggest_method_name(target, symbol_names, ghidra_name)
            if not method:
                continue
            mac = mac_methods.get((lookup_class, method)) or mac_methods.get((spec.class_name, method)) or method
            suggestions.append(
                SlotSuggestion(
                    lookup_class,
                    index,
                    method,
                    mac,
                    f"suggested from {spec.header} vtable 0x{spec.vtable_addr:08x} body 0x{target:08x}",
                )
            )
    return suggestions


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate vtable slot override suggestions.")
    parser.add_argument("--write", action="store_true", help=f"Write to {OUT_PATH.relative_to(REPO)}")
    parser.add_argument("--class", dest="class_name", metavar="NAME", help="Filter to one header class")
    args = parser.parse_args()

    specs = discover_vtable_specs(args.class_name)
    if not specs:
        print("No // VTABLE: headers found.", file=sys.stderr)
        return 1

    suggestions = build_suggestions(specs)
    fieldnames = ["class", "slot_index", "method_name", "mac_method", "note"]
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter="|", lineterminator="\n")
    writer.writerow(fieldnames)
    for row in suggestions:
        writer.writerow([row.to_row()[k] for k in fieldnames])
    output = buf.getvalue()
    print(output, end="")
    if args.write:
        OUT_PATH.write_text(output, encoding="utf-8")
        print(f"wrote {OUT_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
