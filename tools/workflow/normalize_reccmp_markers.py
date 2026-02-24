#!/usr/bin/env python3
"""Normalize reccmp marker formatting across source files."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable


VALID_MARKER_TYPES = {
    "FUNCTION",
    "STUB",
    "SYNTHETIC",
    "TEMPLATE",
    "GLOBAL",
    "VTABLE",
    "STRING",
    "LIBRARY",
    "LINE",
}
MANUAL_OVERRIDE_TYPE = "MANUAL_OVERRIDE_ADDR"
PSEUDO_NO_COLON_TYPES = {MANUAL_OVERRIDE_TYPE, "PROMOTED_FUNCTION"}

MARKER_COLON_RE = re.compile(
    r"^\s*//\s*(?P<type>[A-Za-z_]+)\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+"
    r"(?P<offset>(?:0x)?[0-9a-fA-F]+)(?P<extra>\s+.*)?\s*$"
)
PSEUDO_NO_COLON_RE = re.compile(
    r"^\s*//\s*(?P<type>MANUAL_OVERRIDE_ADDR|PROMOTED_FUNCTION)\s+"
    r"(?P<module>[A-Za-z0-9_]+)\s+"
    r"(?P<offset>(?:0x)?[0-9a-fA-F]+)(?P<extra>\s+.*)?\s*$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["src", "include"],
        help="Files or directories to scan.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write changes in-place. Without this flag only prints planned edits.",
    )
    return parser.parse_args()


def iter_files(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        p = Path(item)
        if p.is_file():
            files.append(p)
            continue
        if p.is_dir():
            for ext in ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx"):
                files.extend(sorted(p.rglob(ext)))

    seen: set[Path] = set()
    ordered: list[Path] = []
    for f in sorted(files):
        rf = f.resolve()
        if rf in seen:
            continue
        seen.add(rf)
        ordered.append(f)
    return ordered


def normalize_offset(raw_offset: str) -> str:
    digits = raw_offset.lower().removeprefix("0x")
    return f"0x{digits}"


def normalize_extra(extra: str | None) -> str:
    if extra is None:
        return ""
    value = extra.strip()
    if not value:
        return ""
    return f" {value}"


def normalize_line(line: str) -> tuple[str, bool]:
    match = MARKER_COLON_RE.match(line)
    if match is not None:
        marker_type = match.group("type").upper()
        module = match.group("module").upper()
        offset = normalize_offset(match.group("offset"))
        extra = normalize_extra(match.group("extra"))

        if marker_type in VALID_MARKER_TYPES:
            normalized = f"// {marker_type}: {module} {offset}{extra}\n"
            return normalized, normalized != line

        if marker_type in PSEUDO_NO_COLON_TYPES:
            normalized = f"// {marker_type} {module} {offset}{extra}\n"
            return normalized, normalized != line

    match = PSEUDO_NO_COLON_RE.match(line)
    if match is not None:
        marker_type = match.group("type").upper()
        module = match.group("module").upper()
        offset = normalize_offset(match.group("offset"))
        extra = normalize_extra(match.group("extra"))
        normalized = f"// {marker_type} {module} {offset}{extra}\n"
        return normalized, normalized != line

    return line, False


def main() -> int:
    args = parse_args()
    files = iter_files(args.paths)

    changed_files = 0
    changed_lines = 0
    for path in files:
        path_posix = path.as_posix()
        if "/ghidra_autogen/" in path_posix:
            continue

        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
        output: list[str] = []
        file_changes = 0
        for line in lines:
            normalized, changed = normalize_line(line)
            output.append(normalized)
            if changed:
                file_changes += 1

        if file_changes > 0:
            changed_files += 1
            changed_lines += file_changes
            print(f"{path}: normalized {file_changes} marker lines")
            if args.write:
                path.write_text("".join(output), encoding="utf-8")

    mode = "write" if args.write else "dry-run"
    print(f"Mode: {mode}")
    print(f"Files changed: {changed_files}")
    print(f"Marker lines normalized: {changed_lines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
