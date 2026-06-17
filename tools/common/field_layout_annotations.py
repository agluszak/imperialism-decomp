"""Parse and validate recovered class field offset annotations in headers.

Standard forms (see docs/reference/field-layout-annotations.md):

1. Same-line field offset (preferred):
     short field04; // +0x04
     TCity* city;  // 0x894 — city production state

2. Previous-line block range (first field in a span):
     // +0xB6..+0xE3 — production need block
     short fieldB6[0x17];

   The range line must end with an em-dash/description (—, --, or " - ").
   Inherited-base diagrams without a dash (e.g. ``0x04..0x90 ... live on TCountry
   base``) must not assign an offset to the next member.

3. Previous-line block start (single field):
     // 0x894 — city production state
     TCity* city;

4. Previous-line range naming the field (legacy, still accepted):
     // 0xB6..0xE4; fieldB6[0x15]/...
     short fieldB6[0x17];

Pad fields (``pad*``, ``padding_*``) are layout-only spacers and are exempt from
explicit offset requirements.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# Same-line or trailing: // +0xNN or // 0xNN (not a .. range on that line).
OFFSET_COMMENT = re.compile(r"//\s*(?:\+)?0x([0-9a-fA-F]+)\b", re.IGNORECASE)

# Range start when the field name appears on the comment line.
RANGE_COMMENT_NAMED = re.compile(r"//\s*(?:\+)?0x([0-9a-fA-F]+)\s*\.\.", re.IGNORECASE)

# Block range on the line before a field: // +0xNN..+0xMM — description
BLOCK_RANGE_COMMENT = re.compile(
    r"^\s*//\s*(?:\+)?0x([0-9a-fA-F]+)\s*\.\.(?:\+)?0x([0-9a-fA-F]+)\s*(?:—|--|\s+-\s+)",
    re.IGNORECASE,
)

# Block start on the line before a field: // 0xNN — description
LINE_START_OFFSET = re.compile(r"^\s*//\s*(?:\+)?0x([0-9a-fA-F]+)\s*(?:—|--|-)", re.IGNORECASE)

LAYOUT_STATUS_COMMENT = re.compile(
    r"^\s*//\s*LAYOUT:\s*(RECOVERED|IN_PROGRESS)\s*$",
    re.IGNORECASE,
)

MEMBER_DECL = re.compile(r"\b([A-Za-z_][\w]*)\s*(?:\[[^\]]*\])?\s*;")


class LayoutRecoveryStatus(Enum):
    RECOVERED = "recovered"
    IN_PROGRESS = "in_progress"


@dataclass(frozen=True)
class FieldOffsetAnnotation:
    field_name: str
    offset: int
    source: str
    line_index: int


def is_pad_field(name: str) -> bool:
    lower = name.lower()
    return lower.startswith("pad") or lower.startswith("padding_")


def field_name_from_decl_line(line: str) -> str | None:
    decl = line.split("//", 1)[0]
    match = MEMBER_DECL.search(decl)
    return match.group(1) if match else None


def field_line_index(lines: list[str], field_name: str) -> int | None:
    pattern = re.compile(rf"\b{re.escape(field_name)}\s*(?:\[[^\]]*\])?\s*;")
    for idx, line in enumerate(lines):
        if pattern.search(line):
            return idx
    return None


def parse_same_line_offset(line: str) -> int | None:
    if ".." in line.split("//", 1)[-1]:
        return None
    match = OFFSET_COMMENT.search(line)
    if match is None:
        return None
    return int(match.group(1), 16)


def _preceding_comment_lines(lines: list[str], line_idx: int, *, max_back: int = 4) -> list[str]:
    collected: list[str] = []
    for back in range(1, max_back + 1):
        prev_idx = line_idx - back
        if prev_idx < 0:
            break
        stripped = lines[prev_idx].strip()
        if stripped.startswith("//"):
            collected.insert(0, stripped)
            continue
        break
    return collected


def resolve_field_offset_from_lines(
    lines: list[str],
    field_name: str,
    line_idx: int | None,
    *,
    name_hints: dict[str, int] | None = None,
) -> tuple[int | None, str]:
    """Return (offset, source_tag) for a field declaration line index."""
    hints = name_hints or {}
    if field_name in hints:
        return hints[field_name], "same_line_hint"

    if line_idx is None:
        return None, "missing"

    line = lines[line_idx]
    same = parse_same_line_offset(line)
    if same is not None:
        return same, "same_line"

    for prev in _preceding_comment_lines(lines, line_idx):
        if field_name in prev:
            range_match = RANGE_COMMENT_NAMED.search(prev)
            if range_match:
                return int(range_match.group(1), 16), "prev_range_named"
            start_match = LINE_START_OFFSET.match(prev)
            if start_match:
                return int(start_match.group(1), 16), "prev_line_start"

    for prev in reversed(_preceding_comment_lines(lines, line_idx)):
        block_range = BLOCK_RANGE_COMMENT.match(prev)
        if block_range:
            return int(block_range.group(1), 16), "prev_block_range"
        start_match = LINE_START_OFFSET.match(prev)
        if start_match:
            return int(start_match.group(1), 16), "prev_line_start"

    return None, "missing"


def build_name_offset_hints(lines: list[str]) -> dict[str, int]:
    hints: dict[str, int] = {}
    for line in lines:
        if ";" not in line:
            continue
        off = parse_same_line_offset(line)
        if off is None:
            continue
        name = field_name_from_decl_line(line)
        if name:
            hints[name] = off
    return hints


def read_header_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def parse_layout_status_comment(lines: list[str]) -> LayoutRecoveryStatus | None:
    for line in lines:
        match = LAYOUT_STATUS_COMMENT.match(line)
        if match:
            raw = match.group(1).upper()
            if raw == "RECOVERED":
                return LayoutRecoveryStatus.RECOVERED
            return LayoutRecoveryStatus.IN_PROGRESS
    return None


def scan_field_annotations(path: Path, class_name: str, field_names: list[str]) -> list[FieldOffsetAnnotation]:
    lines = read_header_lines(path)
    hints = build_name_offset_hints(lines)
    out: list[FieldOffsetAnnotation] = []
    for field_name in field_names:
        if is_pad_field(field_name):
            continue
        line_idx = field_line_index(lines, field_name)
        offset, source = resolve_field_offset_from_lines(
            lines, field_name, line_idx, name_hints=hints
        )
        if offset is not None and line_idx is not None:
            out.append(FieldOffsetAnnotation(field_name, offset, source, line_idx))
    return out
