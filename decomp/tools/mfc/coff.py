#!/usr/bin/env python3
"""Minimal COFF static-library (.lib) + object (.obj) reader for identity matching.

Parses an MSVC-style archive (`!<arch>`) into its COFF object members and, for
each externally-visible function, extracts:

  - the decorated linker symbol,
  - the exact function body bytes (from its section),
  - the byte offsets covered by relocations (call/jmp targets, absolute data
    references) so a caller can mask address-dependent operands.

This is deliberately dependency-free (struct only): the goal is a relocation-masked
normal form of each library function that can be compared against a linked
executable's function bytes, independent of where the linker placed anything.

Only what the matcher needs is implemented (i386 objects, code sections, the
DIR32 / DIR32NB / REL32 relocation types that cover x86 address operands). Import
library members (short-import records / non-i386 machine) are skipped.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

ARCHIVE_MAGIC = b"!<arch>\n"
IMAGE_FILE_MACHINE_I386 = 0x014C

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3

# i386 relocation types whose operand is a 4-byte address field.
REL_I386_DIR32 = 0x0006
REL_I386_DIR32NB = 0x0007
REL_I386_REL32 = 0x0014
MASKABLE_RELOC_TYPES = {REL_I386_DIR32, REL_I386_DIR32NB, REL_I386_REL32}


@dataclass(frozen=True)
class LibraryFunction:
    member: str  # object member name, e.g. "rand.obj"
    symbol: str  # decorated linker symbol, e.g. "_rand"
    size: int  # exact body length in bytes
    body: bytes  # raw function bytes
    reloc_offsets: tuple[int, ...]  # offsets (relative to body start) of 4-byte reloc fields

    def masked(self) -> bytes:
        """Body with each 4-byte relocation field zeroed."""
        return mask_bytes(self.body, self.reloc_offsets)


def mask_bytes(body: bytes, reloc_offsets: tuple[int, ...] | list[int]) -> bytes:
    if not reloc_offsets:
        return body
    buf = bytearray(body)
    for off in reloc_offsets:
        for i in range(off, min(off + 4, len(buf))):
            buf[i] = 0
    return bytes(buf)


@dataclass
class _Section:
    name: str
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    number_of_relocations: int
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(
            self.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
        )


@dataclass
class _Symbol:
    name: str
    value: int
    section_number: int
    storage_class: int


def _read_member_name(raw_name: bytes, longnames: bytes) -> str:
    name = raw_name.rstrip(b" ")
    if name.startswith(b"/") and name[1:].isdigit():
        # "/<offset>" references the longnames ("//") member; MS terminates each
        # name with NUL (not the GNU newline).
        offset = int(name[1:])
        end = longnames.find(b"\x00", offset)
        if end < 0:
            end = len(longnames)
        return longnames[offset:end].rstrip(b"/").decode("ascii", "replace")
    return name.rstrip(b"/").decode("ascii", "replace")


def _basename(member: str) -> str:
    # Members are recorded as Windows paths, e.g. "build\intel\mt_obj\rand.obj".
    return member.replace("\\", "/").rsplit("/", 1)[-1]


def iter_archive_members(data: bytes):
    """Yield (member_name, member_bytes) for each archive member."""
    if data[: len(ARCHIVE_MAGIC)] != ARCHIVE_MAGIC:
        raise ValueError("not an ar archive (bad magic)")
    pos = len(ARCHIVE_MAGIC)
    longnames = b""
    while pos + 60 <= len(data):
        header = data[pos : pos + 60]
        raw_name = header[0:16]
        size = int(header[48:58].decode("ascii", "replace").strip() or "0")
        body_start = pos + 60
        body = data[body_start : body_start + size]
        name_field = raw_name.rstrip(b" ")
        if name_field == b"//":
            longnames = body  # longnames table
        elif name_field == b"/":
            pass  # 1st/2nd linker member (symbol index), not an object
        else:
            yield _read_member_name(raw_name, longnames), body
        pos = body_start + size
        if size % 2 == 1:
            pos += 1  # members are 2-byte aligned (padding newline)


def parse_object_functions(member: str, obj: bytes) -> list[LibraryFunction]:
    """Extract externally-visible code functions from one COFF object member."""
    if len(obj) < 20:
        return []
    (machine, num_sections, _ts, ptr_symtab, num_symbols, opt_size, _chars) = struct.unpack_from(
        "<HHIIIHH", obj, 0
    )
    if machine != IMAGE_FILE_MACHINE_I386:
        return []  # import member or non-i386 object

    section_off = 20 + opt_size
    sections: list[_Section] = []
    for i in range(num_sections):
        base = section_off + i * 40
        if base + 40 > len(obj):
            return []
        name = obj[base : base + 8].rstrip(b"\x00").decode("ascii", "replace")
        (_vsize, _vaddr, raw_size, raw_ptr, reloc_ptr, _lnptr, nreloc, _nln, chars) = struct.unpack_from(
            "<IIIIIIHHI", obj, base + 8
        )
        sections.append(
            _Section(name, raw_size, raw_ptr, reloc_ptr, nreloc, chars)
        )

    # String table follows the symbol table.
    strtab_off = ptr_symtab + num_symbols * 18
    string_table = obj[strtab_off:] if strtab_off < len(obj) else b""

    def sym_name(raw: bytes) -> str:
        if raw[0:4] == b"\x00\x00\x00\x00":
            offset = struct.unpack_from("<I", raw, 4)[0]
            end = string_table.find(b"\x00", offset)
            if end < 0:
                end = len(string_table)
            return string_table[offset:end].decode("ascii", "replace")
        return raw.rstrip(b"\x00").decode("ascii", "replace")

    # Walk the symbol table (skipping aux records).
    symbols_by_section: dict[int, list[_Symbol]] = {}
    idx = 0
    while idx < num_symbols:
        base = ptr_symtab + idx * 18
        if base + 18 > len(obj):
            break
        raw = obj[base : base + 18]
        value, section_number, _type, storage_class, num_aux = struct.unpack_from(
            "<iHHBB", raw, 8
        )
        name = sym_name(raw[0:8])
        if section_number > 0 and storage_class in (
            IMAGE_SYM_CLASS_EXTERNAL,
            IMAGE_SYM_CLASS_STATIC,
        ):
            symbols_by_section.setdefault(section_number, []).append(
                _Symbol(name, value, section_number, storage_class)
            )
        idx += 1 + num_aux

    functions: list[LibraryFunction] = []
    for sec_index, section in enumerate(sections, start=1):
        if not section.is_code or section.size_of_raw_data == 0:
            continue
        syms = symbols_by_section.get(sec_index, [])
        # Function starts are EXTERNAL symbols only. STATIC symbols are internal
        # labels (jump-table targets like memmove's LeadUpVec/UnwindUp*, switch
        # cases) and must NOT bound extents — otherwise a function is truncated at
        # its first internal label. With MSVC /Gy (function-level linking) each
        # function is its own COMDAT section, so an external's extent runs to the
        # next external or the section end.
        externals = sorted(
            (s for s in syms if s.storage_class == IMAGE_SYM_CLASS_EXTERNAL),
            key=lambda s: s.value,
        )
        boundaries = sorted({s.value for s in externals} | {section.size_of_raw_data})
        relocs = _read_relocations(obj, section)
        raw = obj[
            section.pointer_to_raw_data : section.pointer_to_raw_data
            + section.size_of_raw_data
        ]
        for sym in externals:
            start = sym.value
            end = next((b for b in boundaries if b > start), section.size_of_raw_data)
            body, dropped = _trim_padding(raw[start:end])
            if not body:
                continue
            end_trimmed = end - dropped
            offs = tuple(
                sorted(
                    r_va - start
                    for (r_va, r_type) in relocs
                    if start <= r_va < end_trimmed and r_type in MASKABLE_RELOC_TYPES
                )
            )
            functions.append(
                LibraryFunction(
                    member=_basename(member),
                    symbol=sym.name,
                    size=len(body),
                    body=body,
                    reloc_offsets=offs,
                )
            )
    return functions


def _trim_padding(body: bytes) -> tuple[bytes, int]:
    """Strip trailing inter-function alignment padding (int3 0xCC / nop 0x90).

    Object sections are padded to alignment; a linked executable's function size
    (from Ghidra) excludes that tail, so both sides must be normalized to the real
    last instruction byte before comparison. Returns (trimmed, bytes_removed).
    """
    end = len(body)
    while end > 0 and body[end - 1] in (0xCC, 0x90):
        end -= 1
    return body[:end], len(body) - end


def _read_relocations(obj: bytes, section: _Section) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    base = section.pointer_to_relocations
    for i in range(section.number_of_relocations):
        off = base + i * 10
        if off + 10 > len(obj):
            break
        virtual_address, _sym_index, rtype = struct.unpack_from("<IIH", obj, off)
        out.append((virtual_address, rtype))
    return out


def parse_library(path: Path) -> list[LibraryFunction]:
    """Parse every code function from every object member of a .lib archive."""
    data = path.read_bytes()
    functions: list[LibraryFunction] = []
    for member, obj in iter_archive_members(data):
        if not _basename(member).lower().endswith(".obj"):
            continue
        functions.extend(parse_object_functions(member, obj))
    return functions


if __name__ == "__main__":
    import sys

    for arg in sys.argv[1:]:
        funcs = parse_library(Path(arg))
        print(f"{arg}: {len(funcs)} functions from archive")
        for f in funcs:
            if f.member == "rand.obj":
                print(f"  {f.symbol:24} size={f.size} relocs={len(f.reloc_offsets)}")
