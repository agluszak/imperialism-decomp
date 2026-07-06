#!/usr/bin/env python3
"""Decode a turn-event screen-builder function into widget-block pseudo-source.

The turn_event_dialog_factory builders (bd 1uj.51) are long repetitive
widget-construction sequences that Ghidra's decompiler degenerates on. This tool
reads the ORIGINAL binary directly, resolves ILT thunks, names call targets from
config/symbols.csv, extracts the eventCode compare-tree (cmp/je, cmp/jne and
sub/dec ladders), and prints per-case call sequences with pushed arguments
(4-char control tags decoded, e.g. 0x57494e44 -> 'WIND').

usage: uv run python -m tools.binary.decode_builder 0xADDR [--len N]
       (or `just decode-builder 0xADDR`)

The output is a porting aid: each `call helper(args...)` line corresponds to one
source statement (see decomp-loop heuristics note 36 for the widget-block recipe).
Args are printed in source order (right-to-left pushes reversed). Register args
appear by register name — read the listing for those. Length defaults to the
symbols.csv size for the function.
"""

from __future__ import annotations

import re
import struct
import sys

import capstone

from tools.binary.pe import OriginalImage, load_symbol_names, load_symbol_sizes


def decode_tag(value: int) -> str:
    raw = struct.pack("<I", value & 0xFFFFFFFF)
    if all(0x20 <= b < 0x7F for b in raw):
        return f"'{raw.decode()}'({value:#x})"
    return hex(value) if value >= 10 or value < 0 else str(value)


def disasm_function(image: OriginalImage, start: int, length: int):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    fo = image.va_to_file_offset(start)
    if fo is None:
        raise SystemExit(f"address {start:#x} not mapped")
    insns = list(md.disasm(image.data[fo : fo + length], start))
    covered = insns[-1].address + insns[-1].size if insns else start
    while covered < start + length:
        resume = covered + 1
        rfo = image.va_to_file_offset(resume)
        more = list(md.disasm(image.data[rfo : fo + length], resume))
        if not more:
            covered = resume
            continue
        insns += more
        covered = more[-1].address + more[-1].size
    return insns


def extract_cases(insns) -> dict[int, set[int]]:
    """Map case-body address -> eventCode values, from cmp/je, cmp/jne and
    sub/dec equality ladders on eax."""
    cases: dict[int, set[int]] = {}
    ladder_base: int | None = None
    for i, ins in enumerate(insns[:-1]):
        text = f"{ins.mnemonic} {ins.op_str}"
        nxt = insns[i + 1]
        m = re.fullmatch(r"cmp eax, (-?(?:0x)?[0-9a-f]+)", text)
        if m:
            value = int(m.group(1), 0)
            ladder_base = None
            if nxt.mnemonic == "je":
                cases.setdefault(int(nxt.op_str, 16), set()).add(value)
            elif nxt.mnemonic == "jne" and i + 2 < len(insns):
                cases.setdefault(insns[i + 2].address, set()).add(value)
            continue
        m = re.fullmatch(r"sub eax, ((?:0x)?[0-9a-f]+)", text)
        if m:
            ladder_base = int(m.group(1), 0)
            if nxt.mnemonic == "je":
                cases.setdefault(int(nxt.op_str, 16), set()).add(ladder_base)
            continue
        if text == "dec eax" and ladder_base is not None:
            ladder_base += 1
            if nxt.mnemonic == "je":
                cases.setdefault(int(nxt.op_str, 16), set()).add(ladder_base)
            elif nxt.mnemonic == "jne" and i + 2 < len(insns):
                cases.setdefault(insns[i + 2].address, set()).add(ladder_base)
    return cases


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    start = int(argv[0], 16)
    length = None
    for i, a in enumerate(argv):
        if a == "--len":
            length = int(argv[i + 1], 0)

    image = OriginalImage()
    names = load_symbol_names()
    if length is None:
        length = load_symbol_sizes().get(start)
        if length is None:
            print(f"{start:#x} has no size in symbols.csv; pass --len N", file=sys.stderr)
            return 2

    def call_name(addr: int) -> str:
        target = image.resolve_thunk(addr)
        name = names.get(target)
        return f"{name}@{target:#x}" if name else f"sub_{target:x}"

    insns = disasm_function(image, start, length)
    cases = extract_cases(insns)

    print(f"== {names.get(start, '?')} {start:#x} len {length:#x}: {len(cases)} equality cases ==")
    for target in sorted(cases):
        codes = "/".join(sorted(map(hex, cases[target])))
        print(f"  case {codes}: -> {target:#x}")

    print("\n== decode ==")
    pending: list[str] = []
    for ins in insns:
        addr = ins.address
        if addr in cases:
            codes = "/".join(sorted(map(hex, cases[addr])))
            print(f"\n---- case {codes} @ {addr:#x} ----")
            pending = []
        text = f"{ins.mnemonic} {ins.op_str}"
        m = re.fullmatch(r"push (-?(?:0x)?[0-9a-f]+)", text)
        if m:
            pending.append(decode_tag(int(m.group(1), 0)))
            continue
        if ins.mnemonic == "push":
            pending.append(ins.op_str)
            continue
        m = re.fullmatch(r"call (0x[0-9a-f]+)", text)
        if m:
            print(f"  {addr:#x}  {call_name(int(m.group(1), 16))}({', '.join(reversed(pending))})")
            pending = []
            continue
        if ins.mnemonic == "call":
            print(f"  {addr:#x}  call {ins.op_str}  args~({', '.join(reversed(pending))})")
            pending = []
            continue
        m = re.fullmatch(r"mov (e..|dword ptr \[[^\]]+\]), (-?(?:0x)?[0-9a-f]+)", text)
        if m:
            value = int(m.group(2), 0)
            if 0x20202020 <= value <= 0x7F7F7F7F or value > 0xFFFF:
                print(f"  {addr:#x}  {m.group(1)} = {decode_tag(value)}")
            continue
        if ins.mnemonic == "ret":
            print(f"  {addr:#x}  ret")
    return 0


if __name__ == "__main__":
    sys.exit(main())
