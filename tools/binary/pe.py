#!/usr/bin/env python3
"""Direct PE access to the original binary: VA<->file-offset mapping, ILT thunk
resolution, and curated symbol names — without a Ghidra round-trip.

Complements tools/ghidra/raw_disasm.py (which reads bytes through the Ghidra
daemon): these helpers are for batch/scripted analysis where sub-second whole-image
scans matter (jump-table dumps, allocator audits, widget-block decoding).
"""

from __future__ import annotations

import csv
import os
import re
import struct
from pathlib import Path

from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__)

# ILT jump-table band (see docs: 0x401000-0x409ab5 is the jmp thunk region).
ILT_LO = 0x401000
ILT_HI = 0x409AB6


def original_binary_path() -> Path:
    env_path = os.environ.get("ORIGINAL_BINARY")
    if env_path:
        return Path(env_path)
    env_file = REPO_ROOT / ".env"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            m = re.match(r'\s*ORIGINAL_BINARY\s*=\s*"?([^"#]+?)"?\s*$', line)
            if m:
                return Path(m.group(1))
    raise SystemExit("ORIGINAL_BINARY not set (env or .env)")


class OriginalImage:
    """Loaded original PE with VA mapping and thunk resolution."""

    def __init__(self, path: Path | None = None):
        self.path = path or original_binary_path()
        self.data = self.path.read_bytes()
        data = self.data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        self.image_base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
        self.sections: list[tuple[int, int, int]] = []  # (rva, file_off, raw_size)
        off = pe + 24 + opt_size
        for _ in range(nsec):
            _vsize, rva, rsize, raw_off = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append((rva, raw_off, rsize))
            off += 40

    def va_to_file_offset(self, va: int) -> int | None:
        rva = va - self.image_base
        for sec_rva, raw_off, raw_size in self.sections:
            if sec_rva <= rva < sec_rva + raw_size:
                return raw_off + rva - sec_rva
        return None

    def file_offset_to_va(self, fo: int) -> int | None:
        for sec_rva, raw_off, raw_size in self.sections:
            if raw_off <= fo < raw_off + raw_size:
                return self.image_base + sec_rva + fo - raw_off
        return None

    def read_va(self, va: int, size: int) -> bytes:
        fo = self.va_to_file_offset(va)
        if fo is None:
            raise ValueError(f"VA {va:#x} not mapped")
        return self.data[fo : fo + size]

    def resolve_thunk(self, addr: int) -> int:
        """Follow `jmp rel32` chains through the ILT thunk band to the real body."""
        seen: set[int] = set()
        while ILT_LO <= addr < ILT_HI and addr not in seen:
            seen.add(addr)
            fo = self.va_to_file_offset(addr)
            if fo is None or self.data[fo] != 0xE9:
                break
            addr = addr + 5 + struct.unpack_from("<i", self.data, fo + 1)[0]
        return addr

    def jmp_target(self, addr: int) -> int | None:
        """Target of a `jmp rel32` at addr, or None if the byte isn't 0xE9."""
        fo = self.va_to_file_offset(addr)
        if fo is None or self.data[fo] != 0xE9:
            return None
        return addr + 5 + struct.unpack_from("<i", self.data, fo + 1)[0]

    def resolve_fold_chain(self, addr: int, max_hops: int = 8) -> int:
        """Follow a stale-island fold chain to its final body.

        Incremental LINK 5.0 leaves `jmp rel32` islands at a moved/folded
        symbol's old address, chaining island -> ILT thunk -> island -> ... ->
        real body (ctors-dtors-eh skill, 2026-07-23). Unlike resolve_thunk,
        this follows `jmp` hops outside the ILT band too.
        """
        seen: set[int] = set()
        for _ in range(max_hops):
            addr = self.resolve_thunk(addr)
            if addr in seen:
                break
            seen.add(addr)
            target = self.jmp_target(addr)
            if target is None:
                break
            addr = target
        return self.resolve_thunk(addr)


def load_symbol_names() -> dict[int, str]:
    """addr -> curated name from config/original_entities.csv."""
    names: dict[int, str] = {}
    with open(REPO_ROOT / "config" / "original_entities.csv", newline="") as f:
        for row in csv.reader(f, delimiter="|"):
            if len(row) >= 2 and row[0] and re.fullmatch(r"[0-9a-fA-F]+", row[0]):
                names[int(row[0], 16)] = row[1]
    return names


def load_symbol_sizes() -> dict[int, int]:
    """addr -> size (bytes) from config/original_entities.csv function rows."""
    sizes: dict[int, int] = {}
    with open(REPO_ROOT / "config" / "original_entities.csv", newline="") as f:
        for row in csv.reader(f, delimiter="|"):
            if (
                len(row) >= 5
                and row[0]
                and re.fullmatch(r"[0-9a-fA-F]+", row[0])
                and row[4] == "function"
                and row[3].isdigit()
            ):
                sizes[int(row[0], 16)] = int(row[3])
    return sizes
