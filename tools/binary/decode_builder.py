#!/usr/bin/env python3
"""Decode a turn-event screen-builder function into widget-block pseudo-source.

The turn_event_dialog_factory builders (bd 1uj.51) are long repetitive
widget-construction sequences that Ghidra's decompiler degenerates on. This tool
reads the ORIGINAL binary directly, resolves ILT thunks, names call targets from
config/original_entities.csv, extracts the eventCode compare-tree (cmp/je, cmp/jne and
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


# Range/sign conditional jumps MSVC500 emits between a `cmp eax, N` and the
# equality `je`/`jne` when the case sits inside a binary-search switch ladder
# (e.g. `cmp eax, 0x5de` / `jg higher` / `je case`). These do not consume the
# compare's ZF, so the equality jump that resolves value N can follow one.
_RANGE_JUMPS = frozenset(
    {"jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp"}
)


def _find_equality_jump(insns, start: int):
    """Scan forward from `start` for the equality jump that resolves the eax
    compare whose ZF is still live. Steps over range jumps (jg/jl/...) and
    flag-preserving filler (push/pop/nop, and mov to a non-eax destination) that
    MSVC500 schedules between the `cmp` and the `je`/`jne`. Returns
    (case_addr, is_je) or None. The search stops at the first instruction that
    could clobber eax or the compare flags (arithmetic, another cmp/test, a
    call, an unconditional jump, etc.), so it cannot leak into a sibling case.
    """
    for j in range(start, min(start + 8, len(insns))):
        ins = insns[j]
        mn = ins.mnemonic
        if mn == "je":
            return (int(ins.op_str, 16), True)
        if mn == "jne":
            if j + 1 < len(insns):
                return (insns[j + 1].address, False)
            return None
        if mn in _RANGE_JUMPS:
            continue
        if mn in ("push", "pop", "nop"):
            continue
        if mn == "mov":
            dst = ins.op_str.split(",", 1)[0].strip()
            if dst in ("eax", "ax", "al", "ah"):
                return None  # eax redefined -> compare value no longer live
            continue
        return None  # arithmetic/cmp/test/call/jmp/... ends the equality window
    return None


def _immediate(text: str) -> int | None:
    if not re.fullmatch(r"-?(?:0x)?[0-9a-f]+", text):
        return None
    return int(text, 0)


def _jump_target(ins) -> int | None:
    if not ins.op_str.startswith("0x"):
        return None
    return int(ins.op_str, 16)


def _signed32(value: int) -> int:
    return value - 0x100000000 if value >= 0x80000000 else value


def extract_cases(insns, image: OriginalImage | None = None) -> dict[int, set[int]]:
    """Map case-body address to normalized event codes.

    Follow only the entry dispatch while EAX is an affine form of the incoming
    event (``event + offset``).  This preserves the accumulated offset across
    MSVC's chained SUB/DEC ladders, follows binary-search range branches, and
    stops at the first case-body call so body-local EAX comparisons cannot be
    misreported as more cases.
    """
    if not insns:
        return {}

    cases: dict[int, set[int]] = {}

    # Small one-case factories compare the word parameter in memory and never
    # load it into EAX (for example 0x0046fd10). Limit this recognition to the
    # prologue before the first call so body-local stack comparisons are ignored.
    for i, ins in enumerate(insns[:-1]):
        if ins.mnemonic == "call":
            break
        match = re.fullmatch(
            r"word ptr \[esp \+ 0x[0-9a-f]+\], (-?(?:0x)?[0-9a-f]+)",
            ins.op_str,
        )
        if ins.mnemonic != "cmp" or match is None:
            continue
        hit = _find_equality_jump(insns, i + 1)
        if hit is not None:
            cases.setdefault(hit[0], set()).add(int(match.group(1), 0))

    address_to_index = {ins.address: index for index, ins in enumerate(insns)}
    event_load = next(
        (
            index
            for index, ins in enumerate(insns)
            if ins.mnemonic == "movsx"
            and re.fullmatch(r"eax, word ptr \[esp \+ 0x[0-9a-f]+\]", ins.op_str)
        ),
        None,
    )
    start_index = event_load + 1 if event_load is not None else 0
    worklist: list[tuple[int, int, int | None, int | None, int | None]] = [
        (start_index, 0, None, None, None)
    ]
    visited: set[tuple[int, int, int | None, int | None, int | None]] = set()

    while worklist:
        index, offset, equal_event, index_maximum, default_target = worklist.pop()
        while 0 <= index < len(insns):
            state = (index, offset, equal_event, index_maximum, default_target)
            if state in visited:
                break
            visited.add(state)

            ins = insns[index]
            mnemonic = ins.mnemonic
            operands = [part.strip() for part in ins.op_str.split(",", 1)]

            if mnemonic == "cmp" and len(operands) == 2 and operands[0] in ("eax", "ax"):
                value = _immediate(operands[1])
                if value is None:
                    break
                equal_event = value - offset
                index_maximum = value if value >= 0 else None
                index += 1
                continue

            if mnemonic in ("sub", "add") and len(operands) == 2 and operands[0] == "eax":
                value = _immediate(operands[1])
                if value is None:
                    break
                value = _signed32(value)
                offset += -value if mnemonic == "sub" else value
                equal_event = -offset
                index_maximum = None
                default_target = None
                index += 1
                continue

            if mnemonic == "dec" and ins.op_str == "eax":
                offset -= 1
                equal_event = -offset
                index_maximum = None
                default_target = None
                index += 1
                continue

            if mnemonic in ("je", "jz"):
                target = _jump_target(ins)
                if equal_event is not None and target is not None:
                    cases.setdefault(target, set()).add(equal_event)
                equal_event = None
                index_maximum = None
                index += 1
                continue

            if mnemonic in ("jne", "jnz"):
                target = _jump_target(ins)
                if equal_event is not None and index + 1 < len(insns):
                    cases.setdefault(insns[index + 1].address, set()).add(equal_event)
                if target is not None and target in address_to_index:
                    worklist.append((address_to_index[target], offset, None, None, None))
                break

            if mnemonic in _RANGE_JUMPS:
                target = _jump_target(ins)
                if target is not None and target in address_to_index:
                    worklist.append(
                        (address_to_index[target], offset, equal_event, index_maximum, None)
                    )
                if mnemonic in ("ja", "jae") and index_maximum is not None:
                    default_target = target
                index += 1
                continue

            if mnemonic == "jmp":
                target = _jump_target(ins)
                if target is not None and target in address_to_index:
                    index = address_to_index[target]
                    continue
                table_match = re.fullmatch(
                    r"dword ptr \[eax\*4 \+ (0x[0-9a-f]+)\]", ins.op_str
                )
                if image is not None and table_match is not None and index_maximum is not None:
                    table_address = int(table_match.group(1), 16)
                    raw_targets = struct.unpack(
                        f"<{index_maximum + 1}I",
                        image.read_va(table_address, (index_maximum + 1) * 4),
                    )
                    for table_index, case_target in enumerate(raw_targets):
                        if case_target == default_target:
                            continue
                        cases.setdefault(case_target, set()).add(table_index - offset)
                break

            if mnemonic in ("call", "ret"):
                break

            if mnemonic == "mov" and operands and operands[0] in ("eax", "ax", "al", "ah"):
                break
            if mnemonic == "movsx" and operands and operands[0] == "eax":
                if re.fullmatch(r"word ptr \[esp \+ 0x[0-9a-f]+\]", operands[1]):
                    offset = 0
                    equal_event = None
                    index_maximum = None
                    default_target = None
                    index += 1
                    continue
                break
            if mnemonic == "xor" and operands and operands[0] in ("eax", "ax", "al", "ah"):
                break

            # These instructions preserve the compare flags and event expression.
            if mnemonic in ("mov", "push", "pop", "nop", "lea"):
                index += 1
                continue

            # Unknown arithmetic/tests invalidate the equality relation. Keep
            # scanning only while EAX itself remains untouched.
            equal_event = None
            index_maximum = None
            default_target = None
            if operands and operands[0] in ("eax", "ax", "al", "ah"):
                break
            index += 1

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
    cases = extract_cases(insns, image)

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
