#!/usr/bin/env python3
"""Minimal PE32 reader: map a virtual address to the raw file bytes at that VA.

Only what the library-identity matcher needs — read the code bytes of a function
given its VA and length. No imports, no data directories.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_ptr: int


class PEImage:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("not a PE (missing MZ)")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE (missing PE signature)")
        coff_off = e_lfanew + 4
        (_machine, num_sections, _ts, _psym, _nsym, opt_size, _chars) = struct.unpack_from(
            "<HHIIIHH", self.data, coff_off
        )
        opt_off = coff_off + 20
        magic = struct.unpack_from("<H", self.data, opt_off)[0]
        if magic != 0x10B:
            raise ValueError(f"unsupported optional header magic 0x{magic:04x} (need PE32)")
        self.image_base = struct.unpack_from("<I", self.data, opt_off + 28)[0]
        sec_off = opt_off + opt_size
        self.sections: list[_Section] = []
        for i in range(num_sections):
            base = sec_off + i * 40
            (_vsize, vaddr, raw_size, raw_ptr) = struct.unpack_from("<IIII", self.data, base + 8)
            self.sections.append(_Section(vaddr, _vsize, raw_size, raw_ptr))

    def _file_offset(self, va: int) -> int | None:
        rva = va - self.image_base
        for sec in self.sections:
            span = max(sec.virtual_size, sec.raw_size)
            if sec.virtual_address <= rva < sec.virtual_address + span:
                file_off = sec.raw_ptr + (rva - sec.virtual_address)
                if file_off < len(self.data):
                    return file_off
                return None
        return None

    def read_va(self, va: int, size: int) -> bytes | None:
        """Return `size` bytes at virtual address `va`, or None if out of range."""
        off = self._file_offset(va)
        if off is None:
            return None
        chunk = self.data[off : off + size]
        return chunk if len(chunk) == size else None
