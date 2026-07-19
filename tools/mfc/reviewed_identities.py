#!/usr/bin/env python3
"""Loader for config/reviewed_library_identities.csv — the ONE reviewed table.

Each row asserts a confirmed CRT/MFC library identity (name + linker symbol;
prototype is optional enrichment). The central source model treats every row as
a LIBRARY claim; the generated symbols overlay projects the fields; the
library-identity gate requires exact consistency. Accepting an object-matcher
or FID result means editing this CSV — nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows

DEFAULT_REVIEWED = "config/reviewed_library_identities.csv"
REQUIRED_COLUMNS = (
    "address", "name", "symbol", "prototype", "library_family", "object_member",
    "evidence",
)


@dataclass(frozen=True)
class ReviewedIdentity:
    address: int
    name: str
    symbol: str
    prototype: str
    library_family: str
    object_member: str
    evidence: str


# Back-compat alias for the retired applier's class name.
LibraryOverride = ReviewedIdentity


def load_reviewed_identities(path: Path) -> list[ReviewedIdentity]:
    if not path.is_file():
        raise FileNotFoundError(path)
    out: list[ReviewedIdentity] = []
    seen: set[int] = set()
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        for column in REQUIRED_COLUMNS:
            if column not in row:
                raise SystemExit(
                    f"{path}: missing required column '{column}'. Header must be: "
                    f"{'|'.join(REQUIRED_COLUMNS)}"
                )
        address = parse_hex_address(addr_text)
        if address in seen:
            raise SystemExit(f"{path}: duplicate reviewed row for 0x{address:08x}")
        seen.add(address)
        name = (row.get("name") or "").strip()
        symbol = (row.get("symbol") or "").strip()
        if not name or not symbol:
            raise SystemExit(
                f"{path}: 0x{address:08x} needs non-empty name and symbol."
            )
        out.append(ReviewedIdentity(
            address=address,
            name=name,
            symbol=symbol,
            prototype=(row.get("prototype") or "").strip(),
            library_family=(row.get("library_family") or "").strip(),
            object_member=(row.get("object_member") or "").strip(),
            evidence=(row.get("evidence") or "").strip(),
        ))
    return out


# Back-compat alias for the retired applier's function name.
load_overrides = load_reviewed_identities
