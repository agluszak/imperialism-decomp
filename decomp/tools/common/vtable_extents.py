"""Verified original-vtable extents shared by inventory and source-model tooling."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows


@dataclass(frozen=True)
class VerifiedVtableExtent:
    address: int
    slots: int
    class_name: str

    @property
    def end(self) -> int:
        return self.address + self.slots * 4

    def contains_interior(self, address: int) -> bool:
        return self.address < address < self.end


def load_verified_vtable_extents(path: Path) -> tuple[VerifiedVtableExtent, ...]:
    extents: list[VerifiedVtableExtent] = []
    if not path.is_file():
        return ()
    for row in read_pipe_rows(path):
        address = int((row.get("address") or "").strip(), 16)
        slots = int((row.get("slots") or "").strip(), 10)
        class_name = (row.get("class") or "").strip()
        if slots <= 0 or not class_name:
            raise ValueError(f"Invalid verified vtable extent row: {row!r}")
        extents.append(VerifiedVtableExtent(address, slots, class_name))
    return tuple(extents)


def containing_vtable_extent(
    address: int, extents: tuple[VerifiedVtableExtent, ...]
) -> VerifiedVtableExtent | None:
    return next((extent for extent in extents if extent.contains_interior(address)), None)
