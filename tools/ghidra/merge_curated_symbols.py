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
NON_VTABLE_TYPES = {
    "global",
    "data",
    "string",
    "widechar",
    "float",
    "function",
    "template",
    "synthetic",
    "library",
    "stub",
}


@dataclass(frozen=True)
class MergeStats:
    preserved_names: int = 0
    preserved_prototypes: int = 0
    new_from_export: int = 0
    retained_orphans: int = 0
    coerced_vtables: int = 0


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


def coerce_vtable_row(row: dict[str, str], vtable_addrs: set[int]) -> bool:
    addr = addr_key(row.get("address") or "")
    row_type = (row.get("type") or "").strip().lower()
    if addr is None or addr not in vtable_addrs or row_type not in NON_VTABLE_TYPES:
        return False
    row["type"] = "vtable"
    return True


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
    if not curated_by_addr:
        coerced_vtables = 0
        for row in exported_rows:
            if coerce_vtable_row(row, vtable_addrs):
                coerced_vtables += 1
        return exported_rows, MergeStats(
            new_from_export=len(exported_rows), coerced_vtables=coerced_vtables
        )

    merged_addrs: set[int] = set()
    out_rows: list[dict[str, str]] = []
    preserved_names = 0
    preserved_prototypes = 0
    new_from_export = 0
    coerced_vtables = 0

    for row in exported_rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            out_rows.append(row)
            continue
        addr = int(addr_text, 16)
        merged_addrs.add(addr)
        merged = dict(row)
        curated = curated_by_addr.get(addr)
        if curated is None:
            new_from_export += 1
        else:
            curated_name = (curated.get("name") or "").strip()
            if curated_name and merged.get("name", "") != curated_name:
                merged["name"] = curated_name
                preserved_names += 1
            curated_proto = (curated.get("prototype") or "").strip()
            if curated_proto and merged.get("prototype", "") != curated_proto:
                merged["prototype"] = curated_proto
                preserved_prototypes += 1
        if coerce_vtable_row(merged, vtable_addrs):
            coerced_vtables += 1
        out_rows.append(merged)

    retained_orphans = 0
    for addr in sorted(curated_by_addr):
        if addr in merged_addrs:
            continue
        retained = dict(curated_by_addr[addr])
        if coerce_vtable_row(retained, vtable_addrs):
            coerced_vtables += 1
        out_rows.append(retained)
        retained_orphans += 1

    return out_rows, MergeStats(
        preserved_names=preserved_names,
        preserved_prototypes=preserved_prototypes,
        new_from_export=new_from_export,
        retained_orphans=retained_orphans,
        coerced_vtables=coerced_vtables,
    )


def write_symbols_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    import csv

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
