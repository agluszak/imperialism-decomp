#!/usr/bin/env python3
"""Report each factory/builder function's original allocator sequence.

MSVC500 gives each TU a finite inline-expansion budget. `new TWidget()` normally
inlines MFC's `CObject::operator new` away to a direct ::operator new call (g), but
once a TU exhausts its budget the compiler emits out-of-line `call
CObject::operator new` (C, the COMDAT copy at 0x41b1c0) instead — verified
empirically against this toolchain (see mfc_heap_library.cpp). Matching a builder
byte-for-byte therefore requires its TU to flip at the same allocation.

This tool prints, for every original function that allocates through either
allocator, the g/C sequence — the ground truth for arranging recomp TU composition.

usage: uv run python -m tools.binary.alloc_audit [0xADDR ...]
       (or `just alloc-audit`; with no args, scans all functions in symbols.csv
        that call CObject::operator new at least once)
"""

from __future__ import annotations

import re
import sys

import capstone

from tools.binary.pe import OriginalImage, load_symbol_names, load_symbol_sizes

COBJECT_OP_NEW = 0x41B1C0
GLOBAL_OP_NEW = 0x606F73


def alloc_sequence(image: OriginalImage, start: int, size: int) -> str:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    fo = image.va_to_file_offset(start)
    if fo is None:
        return ""
    seq = []
    covered = start
    while covered < start + size:
        chunk = list(md.disasm(image.data[image.va_to_file_offset(covered) : fo + size], covered))
        if not chunk:
            covered += 1
            continue
        for ins in chunk:
            m = re.fullmatch(r"call (0x[0-9a-f]+)", f"{ins.mnemonic} {ins.op_str}")
            if m:
                target = image.resolve_thunk(int(m.group(1), 16))
                if target == COBJECT_OP_NEW:
                    seq.append("C")
                elif target == GLOBAL_OP_NEW:
                    seq.append("g")
        covered = chunk[-1].address + chunk[-1].size
    return "".join(seq)


def main() -> int:
    image = OriginalImage()
    names = load_symbol_names()
    sizes = load_symbol_sizes()

    if len(sys.argv) > 1:
        targets = [int(a, 16) for a in sys.argv[1:]]
    else:
        targets = sorted(sizes)

    explicit = len(sys.argv) > 1
    for addr in targets:
        size = sizes.get(addr)
        if not size:
            continue
        seq = alloc_sequence(image, addr, size)
        if not explicit and "C" not in seq:
            continue
        if not seq:
            continue
        flip = seq.find("C")
        print(
            f"{addr:#x} {names.get(addr, '?'):55.55} allocs={len(seq)} "
            f"inlined={seq.count('g')} outofline={seq.count('C')} "
            f"first_flip={flip if flip >= 0 else '-'}\n    {seq}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
