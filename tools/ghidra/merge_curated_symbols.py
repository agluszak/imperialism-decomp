#!/usr/bin/env python3
"""Merge a fresh Ghidra symbols export with the committed curated symbols.csv."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from tools.common.pipe_csv import read_pipe_table
from tools.common.file_scan import iter_files


VTABLE_MARKER_RE = re.compile(
    r"^\s*//\s*VTABLE\s*:\s*[A-Za-z0-9_]+\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)


@dataclass(frozen=True)
class MergeStats:
    preserved_names: int = 0
    preserved_symbols: int = 0
    preserved_prototypes: int = 0
    preserved_function_types: int = 0
    new_from_export: int = 0
    retained_orphans: int = 0
    dropped_vtable_collisions: int = 0


def addr_key(raw: str) -> int | None:
    text = raw.strip().lower().removeprefix("0x")
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def collect_source_vtable_addresses(repo_root: Path) -> set[int]:
    addrs: set[int] = set()
    for path in iter_files([repo_root / "src", repo_root / "include"]):
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = VTABLE_MARKER_RE.match(line)
            if match is None:
                continue
            addr = addr_key(match.group("offset"))
            if addr is not None:
                addrs.add(addr)
    return addrs


def collides_with_source_vtable(row: dict[str, str], vtable_addrs: set[int]) -> bool:
    """A symbols.csv row at a `// VTABLE:` address must not exist at all: reccmp
    ingests symbols.csv entities after the source markers, so any row here (even
    one typed `vtable`) clobbers the marker-derived vtable name and silently
    breaks the match (see check_vtable_address_collisions). Drop it in the merge
    instead of leaving it for manual deletion after every resync."""
    addr = addr_key(row.get("address") or "")
    return addr is not None and addr in vtable_addrs


def index_symbols_by_address(rows: list[dict[str, str]]) -> dict[int, dict[str, str]]:
    indexed: dict[int, dict[str, str]] = {}
    for row in rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        indexed[int(addr_text, 16)] = row
    return indexed


def merge_curated_symbols_csv(
    fieldnames: list[str],
    exported_rows: list[dict[str, str]],
    curated_by_addr: dict[int, dict[str, str]],
    vtable_addrs: set[int] | None = None,
) -> tuple[list[dict[str, str]], MergeStats]:
    """Keep curated name/prototype for known addresses; append curated-only rows."""
    vtable_addrs = vtable_addrs or set()

    merged_addrs: set[int] = set()
    out_rows: list[dict[str, str]] = []
    preserved_names = 0
    preserved_symbols = 0
    preserved_prototypes = 0
    preserved_function_types = 0
    new_from_export = 0
    dropped_vtable_collisions = 0

    for row in exported_rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            out_rows.append(row)
            continue
        addr = int(addr_text, 16)
        if addr in merged_addrs:
            # The Ghidra export can carry two symbols at one address (e.g. a label
            # and a data symbol); every downstream consumer keys rows by address,
            # so keep only the first.
            continue
        merged_addrs.add(addr)
        merged = dict(row)
        if collides_with_source_vtable(merged, vtable_addrs):
            dropped_vtable_collisions += 1
            continue
        curated = curated_by_addr.get(addr)
        if curated is None:
            new_from_export += 1
        else:
            curated_name = (curated.get("name") or "").strip()
            if curated_name and merged.get("name", "") != curated_name:
                merged["name"] = curated_name
                preserved_names += 1
            curated_symbol = (curated.get("symbol") or "").strip()
            if curated_symbol and merged.get("symbol", "") != curated_symbol:
                merged["symbol"] = curated_symbol
                preserved_symbols += 1
            curated_proto = (curated.get("prototype") or "").strip()
            if curated_proto and merged.get("prototype", "") != curated_proto:
                merged["prototype"] = curated_proto
                preserved_prototypes += 1
            curated_prov = (curated.get("provenance") or "").strip()
            if curated_prov and merged.get("provenance", "") != curated_prov:
                merged["provenance"] = curated_prov
            # A curated `function` row must survive a bare-label export row at the
            # same address. The DB deliberately models some jmp thunks as labels
            # (ILT surgery), but manual source still links against the autogen
            # stubs generated from these rows — demoting type to `global` silently
            # drops the stubs and breaks the link (7 unresolved externs, 2026-07-02).
            if (
                (curated.get("type") or "").strip().lower() == "function"
                and (merged.get("type") or "").strip().lower() != "function"
                and not (merged.get("size") or "").strip()
            ):
                merged["type"] = curated.get("type", "function")
                merged["size"] = (curated.get("size") or "").strip()
                preserved_function_types += 1
        out_rows.append(merged)

    retained_orphans = 0
    for addr in sorted(curated_by_addr):
        if addr in merged_addrs:
            continue
        retained = dict(curated_by_addr[addr])
        if collides_with_source_vtable(retained, vtable_addrs):
            dropped_vtable_collisions += 1
            continue
        out_rows.append(retained)
        retained_orphans += 1

    return out_rows, MergeStats(
        preserved_names=preserved_names,
        preserved_symbols=preserved_symbols,
        preserved_prototypes=preserved_prototypes,
        preserved_function_types=preserved_function_types,
        new_from_export=new_from_export,
        retained_orphans=retained_orphans,
        dropped_vtable_collisions=dropped_vtable_collisions,
    )


def write_symbols_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    import csv

    fieldnames = list(fieldnames)
    for required in ("address", "name", "size", "type", "prototype"):
        if required not in fieldnames:
            fieldnames.append(required)
    if "symbol" not in fieldnames:
        insert_at = fieldnames.index("size") if "size" in fieldnames else len(fieldnames)
        fieldnames.insert(insert_at, "symbol")
    # Optional trailing provenance column: who established the row's name
    # (rtti | mac | manual | ghidra-auto | empty = unknown/legacy).
    if "provenance" not in fieldnames:
        fieldnames.append("provenance")
    for row in rows:
        for field in fieldnames:
            row.setdefault(field, "")

    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def function_names_from_symbols_rows(rows: list[dict[str, str]]) -> dict[int, str]:
    names: dict[int, str] = {}
    for row in rows:
        if (row.get("type") or "").strip().lower() != "function":
            continue
        addr_text = (row.get("address") or "").strip()
        name = (row.get("name") or "").strip()
        if not addr_text or not name:
            continue
        names[int(addr_text, 16)] = name
    return names


def apply_function_names_to_symbols_txt(path: Path, name_by_addr: dict[int, str]) -> int:
    """Rewrite function lines in symbols.ghidra.txt to match symbols.csv names."""
    if not path.is_file() or not name_by_addr:
        return 0

    import re

    ws_re = re.compile(r"\s")
    output: list[str] = []
    renamed = 0

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped:
            output.append(line)
            continue
        parts = stripped.split()
        if len(parts) < 3:
            output.append(line)
            continue
        name, addr_text, kind = parts[0], parts[1], parts[2]
        if kind.lower() != "f":
            output.append(line)
            continue
        try:
            addr = int(addr_text, 16)
        except ValueError:
            output.append(line)
            continue
        curated_name = name_by_addr.get(addr)
        if not curated_name or ws_re.search(curated_name):
            output.append(line)
            continue
        if curated_name != name:
            renamed += 1
        output.append(f"{curated_name} {addr_text} {kind}")

    path.write_text("\n".join(output) + "\n", encoding="utf-8")
    return renamed


def load_curated_symbols(path: Path) -> tuple[list[str], dict[int, dict[str, str]]]:
    if not path.is_file():
        return [], {}
    fieldnames, rows = read_pipe_table(path)
    return fieldnames, index_symbols_by_address(rows)
