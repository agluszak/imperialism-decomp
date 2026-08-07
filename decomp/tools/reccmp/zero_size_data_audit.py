#!/usr/bin/env python3
"""Categorize original-only zero-size DATA roadmap rows with reproducible evidence.

The report is deliberately non-mutating.  It identifies categories that can be
proved from the PE and curated function extents, and leaves uncovered addresses
for listing review rather than guessing a type from a symbol name.
"""
from __future__ import annotations

import argparse
import csv
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from tools.binary.pe import OriginalImage
from tools.common.repo import repo_root_from_file


@dataclass(frozen=True)
class FunctionExtent:
    address: int
    size: int
    name: str


def parse_int(value: str) -> int | None:
    value = value.strip()
    return None if not value else int(value, 0)


def load_function_extents(path: Path) -> list[FunctionExtent]:
    with path.open(encoding="utf-8", newline="") as fd:
        rows = csv.DictReader(fd, delimiter="|")
        functions = [
            FunctionExtent(int(r["address"], 16), int(r["size"] or "0", 0), r["name"])
            for r in rows
            if r["type"].strip().lower() == "function" and r["size"]
        ]
        return sorted(functions, key=lambda item: item.address)


def containing_function(address: int, functions: Iterable[FunctionExtent]) -> FunctionExtent | None:
    # The inventory is small enough that clarity is preferable to another index.
    for fn in functions:
        if fn.address <= address < fn.address + fn.size:
            return fn
    return None


def pointer_run(image: OriginalImage, address: int, limit: int = 64) -> int:
    count = 0
    text_rva, _off, text_size = image.sections[0]
    text_lo = image.image_base + text_rva
    text_hi = text_lo + text_size
    for offset in range(0, limit * 4, 4):
        try:
            target = struct.unpack("<I", image.read_va(address + offset, 4))[0]
        except (ValueError, struct.error):
            break
        if not text_lo <= target < text_hi:
            break
        count += 1
    return count


def categorize(address: int, section: int, functions: list[FunctionExtent], image: OriginalImage) -> tuple[str, str, str]:
    owner = containing_function(address, functions)
    if section == 1 and owner is not None:
        if address == owner.address:
            return "function_start", "function", f"equals curated function {owner.name} start"
        return "function_interior", "label", f"inside {owner.name} [{owner.address:#x},{owner.address + owner.size:#x})"
    if section == 1:
        target = image.jmp_target(address)
        if target is not None:
            return "relative_jump", "thunk", f"PE opcode E9 targets {target:#x}"
        return "uncovered_text", "manual_listing", "in .text; no curated extent or E9 thunk proof"
    run = pointer_run(image, address)
    if run >= 3:
        return "code_pointer_run", "vtable_candidate", f"{run} consecutive pointers into .text"
    return "non_text_data", "manual_xrefs", f"section {section}; no >=3 code-pointer run"


def audit(roadmap_path: Path, entities_path: Path, output: Path, image: OriginalImage) -> dict[str, int]:
    functions = load_function_extents(entities_path)
    counts: dict[str, int] = {}
    findings = []
    with roadmap_path.open(encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd)
        if "pairing_state" not in (reader.fieldnames or ()):
            raise ValueError("roadmap lacks typed schema; regenerate with `just roadmap --csv ...`")
        for row in reader:
            if row.get("row_type") != "data" or row.get("pairing_state") != "unexplained":
                continue
            if parse_int(row.get("size", "")) != 0:
                continue
            address = parse_int(row.get("orig_addr", ""))
            if address is None:
                continue
            section = int(row["orig_sect_ofs"].split(":", 1)[0])
            category, recommendation, evidence = categorize(address, section, functions, image)
            counts[category] = counts.get(category, 0) + 1
            findings.append({"address": f"0x{address:08x}", "name": row.get("name", ""),
                             "section": section, "category": category,
                             "recommendation": recommendation, "evidence": evidence})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=("address", "name", "section", "category", "recommendation", "evidence"))
        writer.writeheader(); writer.writerows(findings)
    return counts


def main() -> int:
    root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--roadmap", type=Path, default=root / "build-msvc500/reccmp_roadmap.csv")
    parser.add_argument("--entities", type=Path, default=root / "config/original_entities.csv")
    parser.add_argument("--output", type=Path, default=root / "build-msvc500/evidence/zero_size_data_audit.csv")
    args = parser.parse_args()
    counts = audit(args.roadmap, args.entities, args.output, OriginalImage())
    print(f"Wrote {args.output}")
    for category, count in sorted(counts.items()): print(f"  {category}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
