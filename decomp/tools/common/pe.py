"""Small PE reader used by comparison triage."""

from __future__ import annotations

import struct


class PeImage:
    """Read image-addressed bytes and data ranges from a PE file."""

    def __init__(self, exe_bytes: bytes):
        self.exe = exe_bytes
        pe = struct.unpack_from("<I", exe_bytes, 0x3C)[0]
        section_count = struct.unpack_from("<H", exe_bytes, pe + 6)[0]
        optional_header_size = struct.unpack_from("<H", exe_bytes, pe + 20)[0]
        self.base = struct.unpack_from("<I", exe_bytes, pe + 0x34)[0]
        offset = pe + 24 + optional_header_size
        self.sections: list[tuple[str, int, int, int]] = []
        for _ in range(section_count):
            name = exe_bytes[offset : offset + 8].rstrip(b"\0").decode()
            virtual_size, virtual_address, _raw_size, raw_offset = struct.unpack_from(
                "<IIII", exe_bytes, offset + 8
            )
            self.sections.append(
                (name, self.base + virtual_address, virtual_size, raw_offset)
            )
            offset += 40

    def read(self, address: int, size: int) -> bytes | None:
        for _name, start, virtual_size, raw_offset in self.sections:
            if start <= address < start + virtual_size:
                offset = raw_offset + (address - start)
                return self.exe[offset : offset + size]
        return None

    def data_ranges(self) -> list[tuple[int, int]]:
        return [
            (start, start + virtual_size)
            for name, start, virtual_size, _raw_offset in self.sections
            if name in (".rdata", ".data")
        ]
