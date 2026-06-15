#!/usr/bin/env python3
"""Reorder reccmp marker blocks in a .cpp file by ascending address.

reccmp-decomplint requires IMPERIALISM markers to appear in increasing virtual-
address order. Keep each marker's leading comment block attached to it, since
the repo intentionally stores explanatory notes immediately above markers.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import re

MARKER_RE = re.compile(
    r"^\s*// (?P<kind>FUNCTION|SYNTHETIC|STUB|LIBRARY|TEMPLATE): (?P<module>\w+) 0x(?P<offset>[0-9a-fA-F]+)"
)


@dataclass(frozen=True)
class FunctionBlock:
    module: str
    offset: int
    ordinal: int
    lines: tuple[str, ...]


def split_markers(lines: list[str]) -> list[tuple[str, int, int, str]] | None:
    markers: list[tuple[str, int, int, str]] = []
    for index, line in enumerate(lines):
        match = MARKER_RE.match(line)
        if match is None:
            continue
        markers.append((match.group("module"), int(match.group("offset"), 16), index, match.group("kind")))
    return markers if len(markers) >= 2 else None


def is_leading_trivia(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("//")


def previous_nonblank_marker_kind(lines: list[str], before: int) -> str | None:
    index = before - 1
    while index >= 0:
        stripped = lines[index].strip()
        if not stripped:
            index -= 1
            continue
        match = MARKER_RE.match(lines[index])
        return match.group("kind") if match is not None else None
    return None


def find_block_starts(lines: list[str], marker_indexes: list[int]) -> list[int]:
    """Return starts that include comments/blanks visually attached to markers."""
    starts: list[int] = []
    previous_marker_index = -1
    for marker_index in marker_indexes:
        start = marker_index
        while start > previous_marker_index + 1:
            candidate = lines[start - 1]
            if MARKER_RE.match(candidate) or not is_leading_trivia(candidate):
                break
            if (
                candidate.strip().startswith("//")
                and previous_nonblank_marker_kind(lines, start - 1) == "SYNTHETIC"
            ):
                break
            if candidate.strip().startswith("//") and "`" in candidate:
                break
            start -= 1
        starts.append(start)
        previous_marker_index = marker_index
    return starts


def normalize_synthetic_nameref(block_lines: tuple[str, ...], marker_kind: str) -> tuple[str, ...]:
    if marker_kind != "SYNTHETIC":
        return block_lines

    lines = list(block_lines)
    marker_index = next((index for index, line in enumerate(lines) if MARKER_RE.match(line)), None)
    if marker_index is None:
        return block_lines

    name_index = marker_index + 1
    while name_index < len(lines) and not lines[name_index].strip():
        name_index += 1
    if name_index >= len(lines):
        return block_lines

    stripped = lines[name_index].strip()
    if MARKER_RE.match(lines[name_index]) or not stripped.startswith("//"):
        return block_lines
    if name_index == marker_index + 1:
        return block_lines

    name_line = lines.pop(name_index)
    lines.insert(marker_index + 1, name_line)
    return tuple(lines)


def reorder_file(path: Path, *, dry_run: bool) -> bool:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    if text and not text.endswith("\n"):
        lines[-1] = lines[-1] + "\n"

    markers = split_markers(lines)
    if markers is None:
        return False

    marker_indexes = [marker[2] for marker in markers]
    block_starts = find_block_starts(lines, marker_indexes)
    prefix = lines[: block_starts[0]]

    blocks: list[FunctionBlock] = []
    normalized = False
    for ordinal, ((module, offset, _marker_index, kind), start) in enumerate(zip(markers, block_starts)):
        end = block_starts[ordinal + 1] if ordinal + 1 < len(block_starts) else len(lines)
        block_lines = tuple(lines[start:end])
        normalized_lines = normalize_synthetic_nameref(block_lines, kind)
        normalized = normalized or normalized_lines != block_lines
        blocks.append(
            FunctionBlock(
                module=module,
                offset=offset,
                ordinal=ordinal,
                lines=normalized_lines,
            )
        )

    original_order = [block.ordinal for block in blocks]
    sorted_blocks = sorted(blocks, key=lambda block: (block.module, block.offset, block.ordinal))
    if [block.ordinal for block in sorted_blocks] == original_order and not normalized:
        return False

    new_lines: list[str] = list(prefix)
    for block in sorted_blocks:
        new_lines.extend(block.lines)

    new_text = "".join(new_lines)
    if new_text == text:
        return False
    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to rewrite.")
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing.")
    return parser.parse_args()


def collect_cpp_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.cpp")))
        elif path.suffix.lower() == ".cpp":
            files.append(path)
    return files


def main() -> int:
    args = parse_args()
    changed = 0
    for path in collect_cpp_files(args.paths):
        if reorder_file(path, dry_run=args.dry_run):
            changed += 1
            print(path)
    print(f"reordered {changed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
