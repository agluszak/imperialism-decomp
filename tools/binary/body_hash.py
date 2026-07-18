#!/usr/bin/env python3
"""Normalized-body comparison for duplicate template COMDAT detection.

The original executable contains multiple bodies for the same MFC template
instantiation (one emitted per referencing TU), differing only by relocations:
call targets to twin helper copies, EH-handler addresses, and vtable/data
addresses. This module disassembles a function from the original binary with
capstone, normalizes every address-like operand to a placeholder, and compares
CALL targets recursively: paired calls must reach the same body or bodies that
are themselves equivalent. That recursion is what separates true per-TU twins
(which call twin copies of the same template helpers) from merely same-shaped
functions (e.g. every scalar deleting destructor calls a structurally
different class destructor, so they correctly compare unequal).

Used by tools.workflow.mfc_collection_audit (twin discovery) and
tools.workflow.template_alias_check (alias evidence validation).
"""

from __future__ import annotations

import capstone

from tools.binary.pe import OriginalImage, load_symbol_sizes

# Any immediate/displacement inside the image's VA span is a relocation-bearing
# operand (code pointer, vtable, global, EH handler) and is normalized away.
_VA_LO = 0x00400000
_VA_HI = 0x006B0000

_MAX_CALL_DEPTH = 2


def _norm_imm(value: int) -> str:
    if _VA_LO <= value < _VA_HI:
        return "<VA>"
    return f"{value:#x}"


def normalized_body(
    img: OriginalImage, addr: int, size: int
) -> tuple[list[str], list[int]]:
    """(normalized instructions, direct-CALL targets in order) for [addr, addr+size)."""
    code = img.read_va(addr, size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    out: list[str] = []
    calls: list[int] = []
    for ins in md.disasm(code, addr):
        parts: list[str] = [ins.mnemonic]
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_REG:
                parts.append(ins.reg_name(op.reg))
            elif op.type == capstone.x86.X86_OP_IMM:
                if ins.mnemonic == "call" and _VA_LO <= op.imm < _VA_HI:
                    calls.append(op.imm)
                parts.append(_norm_imm(op.imm))
            elif op.type == capstone.x86.X86_OP_MEM:
                mem = op.mem
                base = ins.reg_name(mem.base) if mem.base else ""
                index = ins.reg_name(mem.index) if mem.index else ""
                disp = _norm_imm(mem.disp) if mem.disp else "0"
                parts.append(f"[{base}+{index}*{mem.scale}+{disp}]")
        out.append(" ".join(parts))
    return out, calls


def bodies_equivalent(
    img: OriginalImage,
    addr_a: int,
    size_a: int,
    addr_b: int,
    size_b: int,
    sizes: dict[int, int] | None = None,
    _depth: int = _MAX_CALL_DEPTH,
) -> tuple[bool, str]:
    """(equal, reason). Equal = same normalized instruction sequence AND every
    paired direct-call target is the same body or recursively equivalent."""
    if size_a != size_b:
        return False, f"size mismatch ({size_a:#x} vs {size_b:#x})"
    body_a, calls_a = normalized_body(img, addr_a, size_a)
    body_b, calls_b = normalized_body(img, addr_b, size_b)
    if len(body_a) != len(body_b):
        return False, f"instruction count mismatch ({len(body_a)} vs {len(body_b)})"
    for i, (a, b) in enumerate(zip(body_a, body_b)):
        if a != b:
            return False, f"instruction {i} differs: `{a}` vs `{b}`"
    if len(calls_a) != len(calls_b):
        return False, f"call count mismatch ({len(calls_a)} vs {len(calls_b)})"

    if sizes is None:
        sizes = load_symbol_sizes()
    for i, (raw_a, raw_b) in enumerate(zip(calls_a, calls_b)):
        ta, tb = img.resolve_thunk(raw_a), img.resolve_thunk(raw_b)
        if ta == tb:
            continue
        if _depth <= 0:
            return False, f"call {i} targets differ at max depth ({ta:#x} vs {tb:#x})"
        ts_a, ts_b = sizes.get(ta), sizes.get(tb)
        if not ts_a or not ts_b:
            return False, (f"call {i} targets differ and are unsized "
                           f"({ta:#x} vs {tb:#x})")
        try:
            sub_equal, sub_reason = bodies_equivalent(
                img, ta, ts_a, tb, ts_b, sizes, _depth - 1)
        except ValueError:
            return False, f"call {i} target unreadable ({ta:#x} vs {tb:#x})"
        if not sub_equal:
            return False, (f"call {i} targets not equivalent "
                           f"({ta:#x} vs {tb:#x}: {sub_reason})")
    return True, f"{len(body_a)} instructions identical modulo relocations"
