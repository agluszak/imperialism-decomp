#!/usr/bin/env python3
"""Suggest recovered_fields.csv rows from manual include/game/*.h layouts.

Uses pcpp + cxxheaderparser for member extraction; offsets from // +0xNN comments
and class_layout_bases.csv sequential walk.

Usage:
  uv run python -m tools.ghidra.gen_recovered_fields_from_headers
  uv run python -m tools.ghidra.gen_recovered_fields_from_headers --write
  uv run python -m tools.ghidra.gen_recovered_fields_from_headers --class TCity
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.field_layout_annotations import (
    build_name_offset_hints,
    field_line_index,
    is_pad_field,
    read_header_lines,
    resolve_field_offset_from_lines,
)
from tools.common.pipe_csv import read_pipe_rows
from tools.common.recovered_field_type import parse_field_type, to_csv_type
from tools.common.repo import repo_root_from_file
from tools.ghidra.header_preprocess import (
    array_size_value,
    class_name_of,
    fundamental_name,
    parse_header_file,
    type_to_cpp_shape,
)

REPO = repo_root_from_file(__file__)
INCLUDE_GAME = REPO / "include" / "game"
OUT_PATH = REPO / "config" / "recovered_fields.generated.csv"
LAYOUT_BASES_PATH = REPO / "config" / "class_layout_bases.csv"

VTABLE_COMMENT = re.compile(r"//\s*VTABLE:", re.IGNORECASE)


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


def load_layout_bases() -> dict[str, tuple[int, str | None]]:
    rows: dict[str, tuple[int, str | None]] = {}
    if not LAYOUT_BASES_PATH.exists():
        return rows
    for row in read_pipe_rows(LAYOUT_BASES_PATH):
        cls = (row.get("class") or "").strip()
        off_s = (row.get("base_offset") or "").strip()
        if not cls or not off_s:
            continue
        base_class = (row.get("base_class") or "").strip() or None
        rows[cls] = (int(off_s, 16), base_class)
    return rows


def initial_offset(class_name: str, layout_bases: dict[str, tuple[int, str | None]]) -> int:
    if class_name in layout_bases:
        return layout_bases[class_name][0]
    return 4


def extract_class_rows(path: Path, class_name: str, layout_bases: dict[str, tuple[int, str | None]]) -> list[FieldRow]:
    parsed = parse_header_file(path)
    lines = read_header_lines(path)
    name_hints = build_name_offset_hints(lines)
    rows: list[FieldRow] = []

    for scope in parsed.namespace.classes:
        if class_name_of(scope) != class_name:
            continue
        offset = initial_offset(class_name, layout_bases)
        for field in scope.fields:
            if is_pad_field(field.name):
                from cxxheaderparser.types import Array as CxxArray

                if isinstance(field.type, CxxArray):
                    count = array_size_value(field.type)
                    if count is not None:
                        elem = 1
                        if fundamental_name(field.type.array_of) is None:
                            elem = 4
                        offset += count * elem
                else:
                    pad_base, pad_ptr, pad_count, pad_ptr_array = type_to_cpp_shape(field.type)
                    pad_csv = to_csv_type(
                        pad_base,
                        is_ptr=pad_ptr,
                        array_count=pad_count,
                        pointer_array=pad_ptr_array,
                    )
                    pad_spec = parse_field_type(pad_csv)
                    if pad_spec is not None:
                        offset += pad_spec.byte_length
                continue
            base, is_ptr, array_count, pointer_array = type_to_cpp_shape(field.type)
            csv_type = to_csv_type(
                base,
                is_ptr=is_ptr,
                array_count=array_count,
                pointer_array=pointer_array,
            )
            spec = parse_field_type(csv_type)
            if spec is None:
                continue

            line_idx = field_line_index(lines, field.name)
            resolved, _source = resolve_field_offset_from_lines(
                lines, field.name, line_idx, name_hints=name_hints
            )
            if resolved is not None:
                offset = resolved

            if not is_pad_field(field.name):
                rows.append(
                    FieldRow(
                        class_name,
                        offset,
                        csv_type,
                        field.name,
                        f"generated from {path.name}",
                    )
                )
            offset += spec.byte_length
        break
    return rows


def discover_header_paths(
    *,
    only_with_vtable: bool,
    class_filter: str | None,
) -> list[Path]:
    paths = sorted(INCLUDE_GAME.glob("*.h"))
    if only_with_vtable:
        paths = [p for p in paths if VTABLE_COMMENT.search(p.read_text(encoding="utf-8"))]
    if class_filter:
        paths = [p for p in paths if f"class {class_filter}" in p.read_text(encoding="utf-8")]
    return paths


def collect_rows(
    paths: list[Path],
    layout_bases: dict[str, tuple[int, str | None]],
    class_filter: str | None,
) -> list[FieldRow]:
    all_rows: list[FieldRow] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        class_names: list[str] = []
        if class_filter:
            class_names = [class_filter]
        else:
            for match in re.finditer(r"\bclass\s+(\w+)", text):
                name = match.group(1)
                if name not in class_names:
                    class_names.append(name)
        for cls in class_names:
            if cls.endswith("View") and class_filter is None:
                continue
            try:
                all_rows.extend(extract_class_rows(path, cls, layout_bases))
            except Exception:
                continue
    return all_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate recovered_fields suggestions from headers.")
    parser.add_argument("--write", action="store_true", help=f"Write to {OUT_PATH.relative_to(REPO)}")
    parser.add_argument("--class", dest="class_name", metavar="NAME", help="Only emit rows for this class")
    parser.add_argument(
        "--only-with-vtable",
        action="store_true",
        help="Only scan headers containing // VTABLE:",
    )
    args = parser.parse_args()

    layout_bases = load_layout_bases()
    paths = discover_header_paths(
        only_with_vtable=args.only_with_vtable or args.class_name is None,
        class_filter=args.class_name,
    )
    if args.class_name and not paths:
        paths = discover_header_paths(only_with_vtable=False, class_filter=args.class_name)

    all_rows = collect_rows(paths, layout_bases, args.class_name)

    seen: set[tuple[str, int]] = set()
    unique: list[FieldRow] = []
    for row in sorted(all_rows, key=lambda r: (r.class_name, r.offset)):
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
