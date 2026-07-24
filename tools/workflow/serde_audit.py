#!/usr/bin/env python3
"""Audit the TStream serialization surface for save-file byte desync.

The save format is a flat, unframed byte stream: there are no per-record lengths or
sentinels, so a reader that consumes the wrong number of bytes desynchronises every
manager after it. reccmp's match percentage does NOT measure that. An EH-heavy reader
can sit at 39% with perfectly correct byte accounting (TOcean::ReadFrom does), and a
tidy-looking body can silently skip a whole field group (TDiplomacyMgr::ReadFrom did,
by ~2.1 KB, while looking like three clean matrix reads).

This tool measures the thing that actually matters. For each ported ReadFrom/WriteTo it
extracts the ordered sequence of stream operations with their byte widths from two
independent sources and compares them:

  * the ORIGINAL, from the Ghidra listing: every call through a TStream vtable slot,
    with the literal size operand pushed at the call site;
  * OURS, from the manual C++ body.

A divergence in that sequence is a desync candidate. Everything else -- register
allocation, scheduling, EH shape -- is invisible here by construction, which is the
point: this is a correctness oracle, not a score.

Usage:
    just serde-audit                    # full report
    just serde-audit --divergent-only   # just the desync candidates
    just serde-audit --addr 0x4ef080    # one function
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = REPO_ROOT / "build-msvc500" / "evidence" / "serde_audit_listings.json"
BASELINE = REPO_ROOT / "config" / "baselines" / "reccmp_progress_baseline.functions.csv"

# ---------------------------------------------------------------------------
# TStream vtable vocabulary.
#
# Widths and argument counts are not guessed: every slot body is ported and
# 100%-matched in src/game/core/TStream.cpp, so each slot's direction, byte width and
# signature is proven there. `"operand"` means the width is the call site's size
# argument; `None` means variable-length (a 2-byte count prefix plus that many bytes);
# `"object"` means a polymorphic CObject read/write of unknown length.
#
# arg_bytes is what the (thiscall) callee pops, needed to track ESP across calls.
# ---------------------------------------------------------------------------

SLOTS: dict[int, tuple[str, str, object, int]] = {
    # slot: (name, direction, width, arg_bytes)
    0x3C: ("ReadBytes", "read", "operand", 8),
    0x40: ("ReadInteger", "read", 1, 0),
    0x44: ("streamSlot44", "read", 1, 0),
    0x48: ("streamSlot48", "read", 1, 4),
    0x4C: ("ReadShort", "read", 2, 0),
    0x50: ("streamSlot50", "read", 4, 0),
    0x54: ("streamSlot54", "read", 8, 4),
    0x58: ("streamSlot58", "read", 8, 4),
    0x5C: ("streamSlot5c", "read", 16, 4),
    0x60: ("streamSlot60", "read", 16, 4),
    0x64: ("streamSlot64", "read", 4, 4),
    0x68: ("streamSlot68", "read", 4, 0),
    0x6C: ("streamSlot6c", "read", None, 8),
    0x70: ("streamSlot70", "read", None, 8),
    0x74: ("SkipPaddingToEvenByteBoundary", "read", 0, 0),
    0x78: ("WriteBytesSlot78", "write", "operand", 8),
    0x7C: ("streamSlot7c", "write", 1, 4),
    0x80: ("streamSlot80", "write", 1, 4),
    0x84: ("streamSlot84", "write", 1, 4),
    0x88: ("WriteCountSlot88", "write", 2, 4),
    0x8C: ("streamSlot8c", "write", 4, 4),
    0x90: ("streamSlot90", "write", 8, 8),
    0x94: ("streamSlot94", "write", 8, 4),
    0x98: ("streamSlot98", "write", 16, 4),
    0x9C: ("streamSlot9c", "write", 16, 4),
    0xA0: ("streamSlotA0", "write", 4, 4),
    0xA4: ("streamSlotA4", "write", 4, 4),
    0xA8: ("WriteLengthPrefixedCString", "write", None, 4),
    0xAC: ("streamSlotAc", "write", None, 4),
    0xB0: ("ReadByte", "read", "object", 4),
    0xB4: ("WriteObjectSlotB4", "write", "object", 8),
    0xB8: ("WritePaddingToEvenByteBoundary", "write", 0, 0),
}
SLOT_BY_NAME = {name: (slot, direction, width) for slot, (name, direction, width, _) in SLOTS.items()}

# Shared helpers from game/core/stream_byteswap. `swap` entries touch no stream bytes.
HELPERS = {
    "SwapShortArrayBytes": ("swap", 0),
    "ReverseDwordArrayBytes": ("swap", 0),
    "SwapFloat": ("swap", 0),
    "ByteSwapShortInPlace": ("swap", 0),
    "SwapFirstTwoBytesInBuffer": ("swap", 0),
    "ReadByteSwappedShortArrayFromStream": ("read", 2),
    "WriteByteSwappedShortArrayToStream": ("write", 2),
    "WriteShortArrayElems": ("write", 2),
    "WriteShortArrayElemsRev": ("write", 2),
    "WriteIntArrayElems": ("write", 4),
}

SOURCE_OPS = set(SLOT_BY_NAME) | set(HELPERS)

# ---------------------------------------------------------------------------
# Binary side: replay the listing, tracking where the slot pointer lives.
#
# MSVC hoists the slot pointer out of the vtable once and reuses it, either in a
# callee-saved register (`MOV EBX,[EAX+0x3c]` ... `CALL EBX`) or spilled to a stack
# slot (`MOV [ESP+0x18],EBP` ... `CALL dword ptr [ESP+0x18]`). The stack form needs
# ESP tracked across every push/pop/call, because the same textual displacement means
# different slots at different points in the body -- and MSVC happily reuses an
# incoming argument slot as a loop counter once the argument is live in a register.
# ---------------------------------------------------------------------------

SLOT_LOAD_REG = re.compile(r"^\S+\s+MOV (E[A-Z]{2}),\s*dword ptr \[(E[A-Z]{2}) \+ (0x[0-9a-f]+)\]$")
LOAD_STACK_REG = re.compile(r"^\S+\s+MOV (E[A-Z]{2}),\s*dword ptr \[ESP \+ (0x[0-9a-f]+)\]$")
DEREF_REG = re.compile(r"^\S+\s+MOV (E[A-Z]{2}),\s*dword ptr \[(E[A-Z]{2})\]$")
MOV_REG_REG = re.compile(r"^\S+\s+MOV (E[A-Z]{2}),(E[A-Z]{2})$")
SPILL_RE = re.compile(r"^\S+\s+MOV dword ptr \[ESP \+ (0x[0-9a-f]+)\],\s*(E[A-Z]{2})$")
STORE_STACK_IMM = re.compile(r"^\S+\s+MOV dword ptr \[ESP \+ (0x[0-9a-f]+)\],\s*(0x[0-9a-f]+|\d+)$")
CALL_REG = re.compile(r"^\S+\s+CALL (E[A-Z]{2})$")
CALL_STACK = re.compile(r"^\S+\s+CALL dword ptr \[ESP \+ (0x[0-9a-f]+)\]$")
CALL_MEM = re.compile(r"^\S+\s+CALL dword ptr \[(E[A-Z]{2}) \+ (0x[0-9a-f]+)\]$")
CALL_ABS = re.compile(r"^\S+\s+CALL (0x[0-9a-f]+)$")

# Out-of-line stream helpers from game/core/stream_byteswap: not vtable slots, so the
# slot tracker never sees them, but they do move stream bytes.
HELPER_FUNCS = {0x4F2A60: ("read", 2), 0x4B94A0: ("write", 2)}
ILT_RANGE = (0x401000, 0x409AB5)
_ILT_TARGETS: dict[int, int] = {}


def resolve_call_target(address: int) -> int:
    """Chase an ILT jmp thunk to its real target (cached); other addresses pass through."""
    if not (ILT_RANGE[0] <= address <= ILT_RANGE[1]):
        return address
    if address in _ILT_TARGETS:
        return _ILT_TARGETS[address]
    # The ILT row renders as "0x004083a0  (no function) JMP 0x004f2a60", which the
    # instruction filter in listing_lines() drops, so query it raw.
    result = subprocess.run(
        ["uv", "run", "python", "-m", "tools.ghidra.query", "listing", hex(address)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    target = address
    for line in result.stdout.splitlines():
        match = re.search(r"JMP (0x[0-9a-f]+)", line)
        if match:
            target = int(match.group(1), 16)
            break
    _ILT_TARGETS[address] = target
    return target
PUSH_IMM = re.compile(r"^\S+\s+PUSH (0x[0-9a-f]+|\d+)$")
PUSH_ANY = re.compile(r"^\S+\s+PUSH\b")
POP_ANY = re.compile(r"^\S+\s+POP\b")
ADD_ESP = re.compile(r"^\S+\s+ADD ESP,(0x[0-9a-f]+|\d+)$")
SUB_ESP = re.compile(r"^\S+\s+SUB ESP,(0x[0-9a-f]+|\d+)$")
DEST_WRITE = re.compile(r"^\S+\s+(?:MOV|LEA|POP|XOR|ADD|SUB|AND|OR|INC|DEC|IMUL)\s+(E[A-Z]{2})[,\s]")
INSN_RE = re.compile(r"^[0-9a-f]{8}\s+\S")


def listing_lines(address: int, refresh: bool = False) -> list[str]:
    cache: dict[str, list[str]] = {}
    if CACHE_PATH.is_file() and not refresh:
        try:
            cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except ValueError:
            cache = {}
    key = hex(address)
    if key in cache:
        return cache[key]
    result = subprocess.run(
        ["uv", "run", "python", "-m", "tools.ghidra.query", "listing", key],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    lines = [line for line in result.stdout.splitlines() if INSN_RE.match(line)]
    cache[key] = lines
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
    return lines


def binary_stream_ops(address: int) -> tuple[list[dict], list[str]]:
    """Stream ops in the original body, preferring the strict (vtable-verified) pass.

    Strict tracking requires proving the dispatched slot came from the *stream's* vtable.
    When ESP tracking loses the stream register (a shape this replay does not model), the
    strict pass silently reports nothing -- which would read as "the original does no I/O"
    and flag a false desync. Fall back to the offset-only pass in that case and say so.
    """
    strict, warnings = _scan(address, strict=True)
    if strict:
        return strict, warnings
    relaxed, relaxed_warnings = _scan(address, strict=False)
    # Only trust the relaxed pass when it found a raw block read/write. Every real
    # serializer moves bytes through ReadBytes/WriteBytesSlot78; a relaxed pass that
    # turned up only typed-accessor slots has almost certainly matched some other
    # object's vtable at a colliding offset, which is the thing strict mode exists to
    # reject.
    if relaxed and any(op["op"] in ("ReadBytes", "WriteBytesSlot78") for op in relaxed):
        return relaxed, relaxed_warnings + [
            "stream register not tracked; slot offsets matched without vtable proof"
        ]
    return strict, warnings


def _scan(address: int, strict: bool) -> tuple[list[dict], list[str]]:
    ops: list[dict] = []
    warnings: list[str] = []
    reg_slot: dict[str, int] = {}
    stack_slot: dict[int, int] = {}
    # The stream is the serializer's single stack argument (entry-relative +4). Tracking
    # which register holds it, and which holds *its* vtable, is what keeps a dispatch on
    # some other object from being mistaken for a stream call when the slot offsets
    # collide -- TNavyMission::ReadFrom dispatches this->vtable[0x84], and 0x84 is a
    # perfectly good TStream write slot.
    stream_regs: set[str] = set()
    vtable_regs: set[str] = set()
    # The stream's vtable pointer also gets spilled and reloaded (TTown::ReadFrom parks
    # it at entry and reloads it for the tail call), so stack slots have to be tracked
    # for vtables as well as for hoisted slot pointers.
    stack_vtable: set[int] = set()
    esp = 0
    pushed_since_call = 0
    pending_imm: int | None = None

    def emit(slot: int, where: str) -> int:
        nonlocal pending_imm
        name, direction, width, arg_bytes = SLOTS[slot]
        size = width
        if width == "operand":
            if pending_imm is None:
                warnings.append(f"{where}: {name} with a non-literal size operand")
                size = None
            else:
                size = pending_imm
        ops.append({"op": name, "dir": direction, "bytes": size, "count": 1,
                    "at": int(where, 16)})
        return arg_bytes

    lines = listing_lines(address)
    for position, line in enumerate(lines):
        line = line.rstrip()
        where = line.split()[0]

        stack_load = LOAD_STACK_REG.match(line)
        if stack_load:
            key = esp + int(stack_load.group(2), 16)
            if key == 4:
                stream_regs.add(stack_load.group(1))
                vtable_regs.discard(stack_load.group(1))
                continue
            if key in stack_vtable:
                vtable_regs.add(stack_load.group(1))
                stream_regs.discard(stack_load.group(1))
                continue

        deref = DEREF_REG.match(line)
        if deref:
            if deref.group(2) in stream_regs:
                vtable_regs.add(deref.group(1))
            else:
                vtable_regs.discard(deref.group(1))
            stream_regs.discard(deref.group(1))
            continue

        move = MOV_REG_REG.match(line)
        if move:
            for group, register in ((stream_regs, move.group(2)), (vtable_regs, move.group(2))):
                group.add(move.group(1)) if register in group else group.discard(move.group(1))
            continue

        load = SLOT_LOAD_REG.match(line)
        if load:
            if load.group(2) in vtable_regs or not strict:
                reg_slot[load.group(1)] = int(load.group(3), 16)
            else:
                reg_slot.pop(load.group(1), None)
            stream_regs.discard(load.group(1))
            vtable_regs.discard(load.group(1))
            continue

        spill = SPILL_RE.match(line)
        if spill:
            slot = reg_slot.get(spill.group(2))
            key = esp + int(spill.group(1), 16)
            if slot is not None:
                stack_slot[key] = slot
            else:
                stack_slot.pop(key, None)
            if spill.group(2) in vtable_regs:
                stack_vtable.add(key)
            else:
                stack_vtable.discard(key)
            continue

        store_imm = STORE_STACK_IMM.match(line)
        if store_imm:
            key = esp + int(store_imm.group(1), 16)
            stack_slot.pop(key, None)
            stack_vtable.discard(key)
            continue

        push = PUSH_IMM.match(line)
        if push:
            pending_imm = int(push.group(1), 0)
            esp -= 4
            pushed_since_call += 4
            continue
        if PUSH_ANY.match(line):
            esp -= 4
            pushed_since_call += 4
            continue
        if POP_ANY.match(line):
            esp += 4
            continue
        add = ADD_ESP.match(line)
        if add:
            esp += int(add.group(1), 0)
            continue
        sub = SUB_ESP.match(line)
        if sub:
            esp -= int(sub.group(1), 0)
            continue

        slot = None
        stack_call = CALL_STACK.match(line)
        mem_call = CALL_MEM.match(line)
        reg_call = CALL_REG.match(line)
        if stack_call:
            slot = stack_slot.get(esp + int(stack_call.group(1), 16))
        elif mem_call:
            slot = (
                int(mem_call.group(2), 16)
                if (mem_call.group(1) in vtable_regs or not strict)
                else None
            )
            if slot not in SLOTS:
                slot = None
        elif reg_call:
            slot = reg_slot.get(reg_call.group(1))

        abs_call = CALL_ABS.match(line)
        if stack_call or mem_call or reg_call or abs_call:
            helper = None
            if abs_call:
                helper = HELPER_FUNCS.get(resolve_call_target(int(abs_call.group(1), 16)))
            if slot is not None and slot in SLOTS:
                esp += emit(slot, where)
            elif helper is not None:
                direction, element = helper
                ops.append({"op": "stream_helper", "dir": direction, "bytes": element,
                            "count": pending_imm, "at": int(where, 16)})
                esp += pushed_since_call
            else:
                # Unknown callee. A __cdecl callee leaves cleanup to the caller, which
                # shows up as the next instruction being ADD ESP,n -- let that line do
                # the adjustment or the pushes get counted twice. Otherwise the callee
                # popped its own arguments.
                following = lines[position + 1].rstrip() if position + 1 < len(lines) else ""
                if not ADD_ESP.match(following):
                    esp += pushed_since_call
            pushed_since_call = 0
            pending_imm = None
            continue

        dest = DEST_WRITE.match(line)
        if dest:
            reg_slot.pop(dest.group(1), None)
            stream_regs.discard(dest.group(1))
            vtable_regs.discard(dest.group(1))

    return expand_loops(lines, ops), warnings


BACK_JUMP = re.compile(r"^([0-9a-f]{8})\s+J\w+ (0x[0-9a-f]+)$")
DEC_RE = re.compile(r"^\S+\s+DEC (E[A-Z]{2})$")
DEC_STACK = re.compile(r"^\S+\s+DEC dword ptr \[ESP")
MOV_IMM = re.compile(r"^\S+\s+MOV (E[A-Z]{2}),(0x[0-9a-f]+|\d+)$")
MOV_STACK_IMM = re.compile(r"^\S+\s+MOV dword ptr \[ESP \+ 0x[0-9a-f]+\],(0x[0-9a-f]+|\d+)$")
CMP_IMM = re.compile(r"^\S+\s+CMP (?:E[A-Z]{2}|\w+ ptr \[[^]]+\]),(0x[0-9a-f]+|\d+)$")


def expand_loops(lines: list[str], ops: list[dict]) -> list[dict]:
    """Multiply ops inside a counted loop by its trip count.

    The original emits one stream call per loop body; the ported source usually writes
    the same thing as one helper call over N elements. Without expanding the loop the
    two shapes never line up, so this normalises the binary side into the same
    element-wise view the source side produces.

    Only literal trip counts are recovered (`MOV reg,N` ... `DEC reg; JNZ back`, and the
    stack-counter variant). A loop whose count cannot be read keeps count=None, which the
    comparison treats as a wildcard rather than a divergence.
    """
    if not ops:
        return ops
    by_addr = {int(line.split()[0], 16): index for index, line in enumerate(lines)}
    loops = []
    for index, line in enumerate(lines):
        jump = BACK_JUMP.match(line.rstrip())
        if not jump:
            continue
        source = int(jump.group(1), 16)
        target = int(jump.group(2), 16)
        if target < source and target in by_addr:
            loops.append((target, source, by_addr[target], index))
    # innermost first so nested loops multiply correctly
    loops.sort(key=lambda entry: entry[1] - entry[0])
    for start_addr, end_addr, start_index, end_index in loops:
        inner = [op for op in ops if start_addr <= op["at"] <= end_addr]
        if not inner:
            continue
        count = None
        counter = None
        for line in lines[start_index : end_index + 1]:
            dec = DEC_RE.match(line.rstrip())
            if dec:
                counter = dec.group(1)
                break
            if DEC_STACK.match(line.rstrip()):
                counter = "STACK"
                break
        for line in reversed(lines[:start_index]):
            stripped = line.rstrip()
            if counter and counter != "STACK":
                imm = MOV_IMM.match(stripped)
                if imm and imm.group(1) == counter:
                    count = int(imm.group(2), 0)
                    break
            elif counter == "STACK":
                imm = MOV_STACK_IMM.match(stripped)
                if imm:
                    count = int(imm.group(1), 0)
                    break
        if count is None:
            for line in lines[start_index : end_index + 1]:
                cmp_imm = CMP_IMM.match(line.rstrip())
                if cmp_imm:
                    count = None  # bound is a limit, not a trip count; leave unknown
                    break
        for op in inner:
            base = op.get("count")
            op["count"] = None if count is None or base is None else base * count
    return ops


# ---------------------------------------------------------------------------
# Source side.
# ---------------------------------------------------------------------------

MARKER_RE = re.compile(
    r"// FUNCTION: IMPERIALISM (0x[0-9a-fA-F]+)\n[^\n]*?\b(\w+)::(ReadFrom|WriteTo)\s*\("
)
CALL_RE = re.compile(r"\b(" + "|".join(sorted(SOURCE_OPS, key=len, reverse=True)) + r")\s*\(")


def _balanced(text: str, start: int, opener: str, closer: str) -> str:
    depth = 0
    index = start
    while index < len(text):
        if text[index] == opener:
            depth += 1
        elif text[index] == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
        index += 1
    return text[start:]


def _split_args(raw: str) -> list[str]:
    parts, depth, current = [], 0, ""
    for char in raw:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return parts


def _literal(token: str) -> int | None:
    try:
        return int(token.strip(), 0)
    except ValueError:
        return None


# Loop bounds we can read as a literal trip count. Anything else (a field, a count read
# from the stream) yields None, i.e. "repeat count unknown", which the comparison treats
# as a wildcard rather than a divergence.
BOUND_LESS_THAN = re.compile(r"<=?\s*(0x[0-9a-fA-F]+|\d+)\s*[;)]")
BOUND_COUNTDOWN = re.compile(r"=\s*(0x[0-9a-fA-F]+|\d+)\s*;[^;]*!=\s*0\s*;")


def _loop_blocks(body: str) -> list[tuple[int, int, int | None]]:
    """(block start, block end, trip count) for every braced for/while in the body."""
    blocks = []
    for match in re.finditer(r"\b(?:for|while)\s*\(", body):
        open_paren = body.index("(", match.end() - 1)
        header = _balanced(body, open_paren, "(", ")")
        cursor = open_paren + len(header)
        while cursor < len(body) and body[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(body) or body[cursor] != "{":
            continue
        block = _balanced(body, cursor, "{", "}")
        literal = BOUND_COUNTDOWN.search(header) or BOUND_LESS_THAN.search(header)
        blocks.append((cursor, cursor + len(block), int(literal.group(1), 0) if literal else None))

    # do { ... } while (counter != 0): the trip count sits in the counter's last literal
    # assignment before the block, not in the loop header.
    for match in re.finditer(r"\bdo\s*\{", body):
        start = body.index("{", match.start())
        block = _balanced(body, start, "{", "}")
        end = start + len(block)
        tail = body[end : end + 120]
        condition = re.match(r"\s*while\s*\(\s*(\w+)\s*(?:!=\s*0|>\s*0)\s*\)", tail)
        count = None
        if condition:
            assignments = re.findall(
                rf"\b{re.escape(condition.group(1))}\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
                body[:start],
            )
            if assignments:
                count = int(assignments[-1], 0)
        blocks.append((start, end, count))
    return blocks


def _multiplier(blocks: list[tuple[int, int, int | None]], position: int, base: int | None) -> int | None:
    if base is None:
        return None
    total = base
    for start, end, count in blocks:
        if start < position < end:
            if count is None:
                return None
            total *= count
    return total


def source_stream_ops(body: str) -> list[dict]:
    ops: list[dict] = []
    blocks = _loop_blocks(body)
    for match in CALL_RE.finditer(body):
        name = match.group(1)
        raw = _balanced(body, body.index("(", match.end() - 1), "(", ")")[1:-1]
        args = _split_args(raw)
        if name in HELPERS:
            direction, element = HELPERS[name]
            if direction == "swap":
                continue
            count = _literal(args[-1]) if args else None
            ops.append(
                {
                    "op": name,
                    "dir": direction,
                    "bytes": element,
                    "count": _multiplier(blocks, match.start(), count),
                }
            )
            continue
        _, direction, width = SLOT_BY_NAME[name]
        size = _literal(args[1]) if (width == "operand" and len(args) > 1) else width
        if size == "operand":
            size = None
        ops.append(
            {
                "op": name,
                "dir": direction,
                "bytes": size,
                "count": _multiplier(blocks, match.start(), 1),
            }
        )
    return ops


def ported_serializers() -> dict[int, dict]:
    found: dict[int, dict] = {}
    for path in sorted((REPO_ROOT / "src").rglob("*.cpp")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "ReadFrom" not in text and "WriteTo" not in text:
            continue
        for match in MARKER_RE.finditer(text):
            body = _balanced(text, text.index("{", match.end() - 1), "{", "}")
            found[int(match.group(1), 16)] = {
                "name": f"{match.group(2)}::{match.group(3)}",
                "file": str(path.relative_to(REPO_ROOT)),
                "ops": source_stream_ops(body),
            }
    return found


# ---------------------------------------------------------------------------
# Comparison and reporting.
# ---------------------------------------------------------------------------


def compare(original: list[dict], ported: list[dict]) -> dict:
    """Compare direction and byte width in order.

    A `None` width (sizeof(...) on our side, a computed size on the original's) is a
    wildcard: it cannot prove a divergence, so it is counted and reported instead.
    """
    unverified = 0
    limit = min(len(original), len(ported))
    for index in range(limit):
        left, right = original[index], ported[index]
        if left["dir"] != right["dir"]:
            return {"status": "divergent", "index": index, "unverified": unverified}
        if left["bytes"] is None or right["bytes"] is None:
            unverified += 1
        elif left["bytes"] != right["bytes"]:
            return {"status": "divergent", "index": index, "unverified": unverified}
        if left.get("count") is None or right.get("count") is None:
            unverified += 1
        elif left["count"] != right["count"]:
            return {"status": "divergent", "index": index, "unverified": unverified}
    if len(original) != len(ported):
        return {"status": "divergent", "index": limit, "unverified": unverified}
    return {"status": "aligned", "index": None, "unverified": unverified}


def load_scores() -> dict[int, float]:
    if not BASELINE.is_file():
        return {}
    with BASELINE.open(encoding="utf-8") as handle:
        return {
            int(row["address"], 16): float(row["matching"]) * 100.0
            for row in csv.DictReader(handle, delimiter="|")
        }


def _brief(ops: list[dict], upto: int) -> str:
    window = ops[max(0, upto - 2) : upto + 3]
    def render(op: dict) -> str:
        size = op["bytes"] if op["bytes"] is not None else "?"
        count = op.get("count")
        return f"{op['dir'][0]}{size}" + (f"x{count}" if count not in (1, None) else ("x?" if count is None else ""))

    return ", ".join(render(op) for op in window)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addr", action="append", default=[], help="audit only these addresses")
    parser.add_argument("--divergent-only", action="store_true", help="print only desync candidates")
    parser.add_argument(
        "--check", action="store_true", help="exit non-zero when desync candidates remain"
    )
    args = parser.parse_args(argv)

    serializers = ported_serializers()
    if args.addr:
        wanted = {int(value, 16) for value in args.addr}
        serializers = {a: v for a, v in serializers.items() if a in wanted}

    scores = load_scores()
    divergent, aligned, artifacts = [], [], []

    for address, info in sorted(serializers.items()):
        original, warnings = binary_stream_ops(address)
        row = {
            "address": address,
            "name": info["name"],
            "file": info["file"],
            "score": scores.get(address),
            "original": original,
            "ported": info["ops"],
            "warnings": warnings,
            **compare(original, info["ops"]),
        }
        if row["status"] == "aligned":
            aligned.append(row)
        elif row["score"] is not None and row["score"] >= 99.995:
            # Self-calibration: a 100%-exact function compiles to the original's bytes,
            # so its stream behaviour is identical by construction. A divergence flagged
            # here is therefore a limitation of this tool (usually a same-class helper
            # holding the real ops, or a shape it cannot expand), never a real desync.
            artifacts.append(row)
        else:
            divergent.append(row)

    total_unverified = sum(row["unverified"] for row in aligned + divergent + artifacts)
    print(f"serializers audited: {len(serializers)}")
    print(f"  byte-aligned with the original  : {len(aligned)}")
    print(f"  DESYNC CANDIDATES               : {len(divergent)}")
    print(f"  tool artifacts (function exact) : {len(artifacts)}")
    print(f"  widths not provable either side : {total_unverified} (sizeof/computed sizes)")
    print()
    print("A divergence is a save-file desync candidate. A low reccmp score with no")
    print("divergence is a codegen/EH-shape issue and cannot corrupt a load.")
    print()

    for row in sorted(divergent, key=lambda r: r["index"]):
        score = f"{row['score']:.1f}%" if row["score"] is not None else "   -  "
        print(f"[DESYNC?] 0x{row['address']:06x} {score:>7} {row['name']}  ({row['file']})")
        print(f"          diverges at stream op #{row['index']}  "
              f"(original has {len(row['original'])} ops, ported has {len(row['ported'])})")
        print(f"          original: {_brief(row['original'], row['index'])}")
        print(f"          ported  : {_brief(row['ported'], row['index'])}")
        for warning in row["warnings"][:2]:
            print(f"          note: {warning}")
        print()

    if not args.divergent_only and artifacts:
        print("tool artifacts -- these functions are 100%-exact, so their stream")
        print("behaviour matches by construction; the divergence is this tool's blind spot:")
        for row in artifacts:
            print(f"  0x{row['address']:06x} {row['name']} "
                  f"(original {len(row['original'])} ops, ported {len(row['ported'])})")
        print()

    if not args.divergent_only and aligned:
        print("byte-aligned:")
        for row in aligned:
            score = f"{row['score']:.1f}%" if row["score"] is not None else "   -  "
            suffix = f"  ({row['unverified']} unverified widths)" if row["unverified"] else ""
            print(f"  0x{row['address']:06x} {score:>7} {row['name']}{suffix}")

    return 1 if (divergent and args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
