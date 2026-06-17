#!/usr/bin/env python3
"""Suggest recovered_fields.csv rows from manual include/game/*.h layouts.

Parses explicit offset comments (// +0xNN, // 0xNN) and simple member declarations
to emit pipe-delimited rows for review/merge into config/recovered_fields.csv.

Usage:
  uv run python -m tools.ghidra.gen_recovered_fields_from_headers
  uv run python -m tools.ghidra.gen_recovered_fields_from_headers --write
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.repo import repo_root_from_file

REPO = repo_root_from_file(__file__)
INCLUDE_GAME = REPO / "include" / "game"
OUT_PATH = REPO / "config" / "recovered_fields.generated.csv"

# Layout anchors from recovered RTTI / manual headers (bytes).
CLASS_PREFIX_SIZE: dict[str, int] = {
    "TGreatPower": 0x94,  # TCountry base through ownedRegionList
    "TCity": 0x04,  # after vftable
}

TYPE_SIZES: dict[str, int] = {
    "unsigned char": 1,
    "signed char": 1,
    "char": 1,
    "bool": 1,
    "short": 2,
    "unsigned short": 2,
    "int": 4,
    "unsigned int": 4,
    "long": 4,
    "unsigned long": 4,
    "float": 4,
    "double": 8,
}

POINTER_TYPES = {"void", "CString", "TPtrList", "TQueueObject", "TCity", "TGreatPower"}
POINTER_SUFFIX = re.compile(r"^(.+?)\s*\*\s*$")
ARRAY_SUFFIX = re.compile(r"^(.+?)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]\s*;?\s*$")
MEMBER_LINE = re.compile(
    r"^\s*(?:(?:unsigned|signed)\s+)?(?:char|short|int|long|float|double|bool|void|class\s+)?"
    r"([\w:]+)\s*(\*?)\s*(?:\[\s*(0x[0-9a-fA-F]+|\d+)\s*\])?\s*;\s*$"
)
OFFSET_COMMENT = re.compile(r"//\s*(?:\+)?0x([0-9a-fA-F]+)\b", re.IGNORECASE)
RANGE_COMMENT = re.compile(r"//\s*0x([0-9a-fA-F]+)\s*\.\.", re.IGNORECASE)


@dataclass
class FieldRow:
    class_name: str
    offset: int
    field_type: str
    field_name: str
    note: str

    def to_csv(self) -> str:
        return (
            f"{self.class_name}|0x{self.offset:x}|{self.field_type}|{self.field_name}|{self.note}"
        )


def sizeof_type(type_name: str, is_ptr: bool, array_count: int | None) -> tuple[str, int]:
    if array_count is not None:
        elem = type_name.rstrip("*").strip()
        if is_ptr or elem in POINTER_TYPES or elem.startswith("T"):
            csv_type = f"{elem}[0x{array_count:x}]" if array_count > 9 else f"{elem}[{array_count}]"
            return csv_type.replace("**", "*"), 4 * array_count if is_ptr else _scalar_size(elem) * array_count
        csv_type = f"{elem}[0x{array_count:x}]" if array_count > 9 else f"{elem}[{array_count}]"
        return csv_type, _scalar_size(elem) * array_count
    if is_ptr:
        base = type_name.rstrip("*").strip()
        return base if base in POINTER_TYPES or base.startswith("T") else f"{base}*", 4
    return type_name, _scalar_size(type_name)


def _scalar_size(type_name: str) -> int:
    for key, size in TYPE_SIZES.items():
        if type_name == key or type_name.endswith(key):
            return size
    return 4


def parse_header(path: Path, class_name: str) -> list[FieldRow]:
    rows: list[FieldRow] = []
    text = path.read_text(encoding="utf-8")
    if f"class {class_name}" not in text:
        return rows

    in_class = False
    offset = CLASS_PREFIX_SIZE.get(class_name, 4)
    pending_range: int | None = None

    for line in text.splitlines():
        if re.search(rf"\bclass\s+{class_name}\b", line):
            in_class = True
            continue
        if not in_class:
            continue
        if line.strip().startswith("class ") and class_name not in line:
            break
        if line.strip() == "};":
            break
        if line.strip().startswith("virtual "):
            continue

        range_m = RANGE_COMMENT.search(line)
        if range_m:
            pending_range = int(range_m.group(1), 16)
            continue

        off_m = OFFSET_COMMENT.search(line)
        if off_m and ".." not in line:
            offset = int(off_m.group(1), 16)

        member_m = MEMBER_LINE.match(line.replace("class ", ""))
        if not member_m:
            continue

        name = member_m.group(1)
        is_ptr = member_m.group(2) == "*"
        arr = member_m.group(3)
        array_count = int(arr, 16) if arr and arr.lower().startswith("0x") else int(arr) if arr else None

        if pending_range is not None:
            offset = pending_range
            pending_range = None

        type_token = "void" if is_ptr else "int"
        if "short" in line:
            type_token = "short"
        elif "unsigned char" in line or "signed char" in line:
            type_token = "unsigned char"
        elif "int" in line and "short" not in line:
            type_token = "int"

        csv_type, size = sizeof_type(type_token if not is_ptr else name, is_ptr, array_count)
        if is_ptr and not csv_type.endswith("*") and "[" not in csv_type:
            csv_type = name

        rows.append(
            FieldRow(
                class_name,
                offset,
                csv_type,
                name,
                f"generated from {path.name}",
            )
        )
        offset += size

    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate recovered_fields suggestions from headers.")
    parser.add_argument(
        "--write",
        action="store_true",
        help=f"Write suggestions to {OUT_PATH.relative_to(REPO)}",
    )
    args = parser.parse_args()

    targets = [
        (INCLUDE_GAME / "TGreatPower.h", "TGreatPower"),
        (INCLUDE_GAME / "TCity.h", "TCity"),
        (INCLUDE_GAME / "TCountry.h", "TCountry"),
    ]
    all_rows: list[FieldRow] = []
    for path, cls in targets:
        if path.exists():
            all_rows.extend(parse_header(path, cls))

    # Deduplicate by class+offset keeping first.
    seen: set[tuple[str, int]] = set()
    unique: list[FieldRow] = []
    for row in all_rows:
        key = (row.class_name, row.offset)
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)

    lines = ["class|offset|field_type|field_name|note", *[r.to_csv() for r in unique]]
    output = "\n".join(lines) + "\n"
    print(output)
    if args.write:
        OUT_PATH.write_text(output, encoding="utf-8")
        print(f"wrote {OUT_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
