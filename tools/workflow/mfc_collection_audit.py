#!/usr/bin/env python3
"""Audit an embedded MFC collection member: offset, template identity evidence,
duplicate-COMDAT (twin) detection, and a mismatch classification.

Reads the ORIGINAL binary directly (capstone, no Ghidra round-trip). For an
owner constructor it reports every embedded vtable write with:

- member offset and vtable address(es);
- vtable extent and slot-0 identity (inherited CObject::GetRuntimeClass =>
  template specialization; concrete CPtrList/CObList/... => concrete class);
- the CList block-size store when present (offset+0x18);
- every function referencing each vtable (ctor/dtor copy census);
- normalized-body twin scan: for each vtable slot target, other same-size
  functions in symbols.csv whose bodies are identical modulo relocations
  (per-TU duplicate template COMDATs -> template_aliases.csv candidates);
- a classification from the mfc-collections skill taxonomy.

The classifier exists to stop a specific failure mode: seeing an unpaired
duplicate template destructor and "fixing" it by replacing the embedded member
with raw storage. A TWIN_TEMPLATE_COMDAT verdict means the source model is
fine and the gap belongs in comparison metadata.

usage:
  just mfc-collection-audit 0xCTOR [0xCTOR2 ...]
  just mfc-collection-audit CIncludeView
"""

from __future__ import annotations

import struct
import sys

import capstone
from capstone import x86

from tools.binary.body_hash import bodies_equivalent
from tools.binary.pe import OriginalImage, load_symbol_names, load_symbol_sizes

# Curated slot-0 identities (config/symbols.csv names). CObject's inherited
# GetRuntimeClass on a template vtable is the "no own CRuntimeClass" tell.
_TEMPLATE_SLOT0_MARK = "CObject::GetRuntimeClass"
_CONCRETE_MARKS = ("CPtrList::", "CObList::", "CObArray::", "CStringList::",
                   "CWordArray::", "CDWordArray::", "CByteArray::")

_CODE_LO = 0x00401000
_CODE_HI = 0x00630000
_RDATA_LO = 0x00630000
_RDATA_HI = 0x00680000


def _parse_target(arg: str, names: dict[int, str]) -> int | None:
    if arg.lower().startswith("0x"):
        return int(arg, 16)
    for addr, name in names.items():
        if name == f"{arg}::{arg}":
            return addr
    return None


def _vtable_extent(img: OriginalImage, vtbl: int) -> list[int]:
    """Slot targets until the first non-code pointer (max 64 slots)."""
    slots: list[int] = []
    for i in range(64):
        raw = img.read_va(vtbl + 4 * i, 4)
        if len(raw) < 4:
            break
        ptr = struct.unpack("<I", raw)[0]
        if not (_CODE_LO <= ptr < _CODE_HI):
            break
        slots.append(ptr)
    return slots


def _rdata_refs_to(img: OriginalImage, va: int) -> list[int]:
    """Code VAs of `mov [..], imm32=va` style writers: scan code for the imm bytes."""
    needle = struct.pack("<I", va)
    hits: list[int] = []
    lo_fo = img.va_to_file_offset(_CODE_LO)
    hi_fo = img.va_to_file_offset(_CODE_HI - 1)
    if lo_fo is None or hi_fo is None:
        return hits
    start = lo_fo
    while True:
        idx = img.data.find(needle, start, hi_fo)
        if idx < 0:
            break
        ref_va = img.file_offset_to_va(idx)
        if ref_va is not None:
            hits.append(ref_va)
        start = idx + 1
    return hits


def _enclosing_function(addr: int, sizes: dict[int, int]) -> int | None:
    best = None
    for start, size in sizes.items():
        if start <= addr < start + max(size, 1):
            if best is None or start > best:
                best = start
    return best


def _find_twins(img: OriginalImage, addr: int, names: dict[int, str],
                sizes: dict[int, int]) -> list[tuple[int, str]]:
    """Same-size symbols whose normalized bodies match `addr` exactly."""
    size = sizes.get(addr)
    if not size or size < 8:
        return []
    twins: list[tuple[int, str]] = []
    for cand, cand_size in sizes.items():
        if cand == addr or cand_size != size:
            continue
        if not (_CODE_LO <= cand < _CODE_HI):
            continue
        try:
            equal, _ = bodies_equivalent(img, addr, size, cand, cand_size, sizes)
        except ValueError:
            continue
        if equal:
            twins.append((cand, names.get(cand, "?")))
    return twins


def audit_ctor(img: OriginalImage, ctor: int, names: dict[int, str],
               sizes: dict[int, int]) -> int:
    size = sizes.get(ctor)
    name = names.get(ctor, "?")
    print("=" * 72)
    print(f"Owner ctor:      {ctor:#010x}  {name}  (size {size or '?'})")
    if not size:
        print("  no size in symbols.csv -- cannot disassemble; is this a function?")
        return 1

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    code = img.read_va(ctor, size)

    # (member_offset, vtable_va, insn_va); offset None = store through bare [reg].
    vptr_writes: list[tuple[int | None, int, int]] = []
    block_stores: dict[int, int] = {}  # store offset -> immediate
    for ins in md.disasm(code, ctor):
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if dst.type != x86.X86_OP_MEM or src.type != x86.X86_OP_IMM:
            continue
        if dst.mem.index != 0 or dst.mem.base == 0:
            continue
        off = dst.mem.disp
        if _RDATA_LO <= src.imm < _RDATA_HI:
            vptr_writes.append((off, src.imm, ins.address))
        elif 0 < src.imm < 0x100 and dst.size == 4:
            block_stores[off] = src.imm

    if not vptr_writes:
        print("  no embedded vtable writes found in the ctor body.")
        return 0

    rc = 0
    for off, vtbl, insn_va in vptr_writes:
        slots = _vtable_extent(img, vtbl)
        slot0 = img.resolve_thunk(slots[0]) if slots else 0
        slot0_name = names.get(slot0, "?")
        if _TEMPLATE_SLOT0_MARK in slot0_name:
            family = "template specialization (CList<>/CMap<>/CArray<>: no own CRuntimeClass)"
        elif any(m in slot0_name for m in _CONCRETE_MARKS):
            family = f"concrete MFC class ({slot0_name.split('::')[0]})"
        elif "::GetRuntimeClass" in slot0_name:
            family = (f"own CRuntimeClass ({slot0_name.split('::')[0]}) -- a real class "
                      f"vtable (owner or base), not a template member")
        else:
            family = "UNKNOWN -- verify slot-0 identity by hand"

        print(f"\nMember offset:   +{off:#x}  (vptr store at {insn_va:#x})")
        print(f"Vtable:          {vtbl:#010x}  ({len(slots)} code slots)")
        print(f"Slot 0:          {slot0:#010x}  {slot0_name}")
        print(f"Family:          {family}")
        blk = block_stores.get(off + 0x18)
        if blk is not None:
            print(f"Block size:      {blk}  (store to +{off + 0x18:#x}; CList ctor arg)")

        # Ctor/dtor copy census: every function embedding this vtable address.
        writers = sorted({f for r in _rdata_refs_to(img, vtbl)
                          if (f := _enclosing_function(r, sizes)) is not None})
        print(f"Vtable writers:  {len(writers)}")
        for w in writers:
            print(f"  {w:#010x}  {names.get(w, '?')}")

        # Twin scan over the vtable's slot bodies. A body equal modulo relocations
        # AND carrying the same curated name is a per-TU duplicate COMDAT of the
        # same instantiation (alias-row candidate). Equal-shape bodies under a
        # DIFFERENT name are distinct instantiations over trivially-destructible
        # elements that genuinely compile identically -- summarized, not aliased.
        twin_found = False
        seen_targets: set[int] = set()
        for i, raw_tgt in enumerate(slots[:8]):
            tgt = img.resolve_thunk(raw_tgt)
            if tgt in seen_targets:
                continue
            seen_targets.add(tgt)
            tgt_name = names.get(tgt, "?")
            twins = _find_twins(img, tgt, names, sizes)
            same_name = [(a, n) for a, n in twins if n == tgt_name and n != "?"]
            other = [t for t in twins if t not in same_name]
            if same_name or other:
                print(f"  slot {i}: {tgt:#010x} {tgt_name}")
            for taddr, tname in same_name:
                twin_found = True
                print(f"    TWIN {taddr:#010x} (same instantiation, identical modulo "
                      f"relocations) -> config/template_aliases.csv candidate")
            if other:
                print(f"    ({len(other)} equal-shape bodies of OTHER instantiations "
                      f"-- not aliases)")
        if twin_found:
            print("Classification:  TWIN_TEMPLATE_COMDAT -- source model is correct;")
            print("                 record aliases, do NOT re-model the member.")
        elif family.startswith("own CRuntimeClass"):
            print("Classification:  OWNER_OR_BASE_VTABLE (not a collection member)")
        elif family.startswith("UNKNOWN"):
            print("Classification:  NEEDS_REVIEW (unrecognized slot-0 identity)")
            rc = 1
        else:
            print("Classification:  EMBEDDED_MEMBER_OK (verify exact template args:")
            print("                 block size, element stride, destruction, ARG_TYPE)")
    return rc


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    img = OriginalImage()
    names = load_symbol_names()
    sizes = load_symbol_sizes()
    rc = 0
    for arg in argv:
        target = _parse_target(arg, names)
        if target is None:
            print(f"cannot resolve {arg!r} to a ctor address "
                  f"(want 0xADDR or a class with a Class::Class symbol)", file=sys.stderr)
            rc = 2
            continue
        rc = max(rc, audit_ctor(img, target, names, sizes))
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
