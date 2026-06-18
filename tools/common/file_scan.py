#!/usr/bin/env python3
"""Shared source file scanning helpers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


CPP_HEADER_PATTERNS = ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx")

# `gen_class` maintains a marked, auto-generated reference block inside hand-owned
# headers. Its slot table embeds raw provisional Ghidra names that can incidentally
# match banned-pattern regexes (bridge names, etc.). Source-policy gates that scan
# for *hand-written* anti-patterns must skip these blocks; the manifest-gate already
# guards their correctness.
_GENERATED_BLOCK_RE = re.compile(
    r"^[ \t]*//[ \t]*===[ \t]*BEGIN GENERATED \(\w+\).*?^[ \t]*//[ \t]*===[ \t]*END GENERATED \(\w+\)[ \t]*===[ \t]*$",
    re.DOTALL | re.MULTILINE,
)


def strip_generated_blocks(text: str) -> str:
    """Blank out gen_class GENERATED blocks (keeping line count) before pattern scans."""
    def _blank(match: re.Match[str]) -> str:
        return "\n".join("" for _ in match.group(0).splitlines())

    return _GENERATED_BLOCK_RE.sub(_blank, text)


def iter_files(paths: Iterable[str], patterns: Iterable[str] = CPP_HEADER_PATTERNS) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_file():
            files.append(path)
            continue
        if path.is_dir():
            for pattern in patterns:
                files.extend(sorted(path.rglob(pattern)))

    seen: set[Path] = set()
    ordered: list[Path] = []
    for path in sorted(files):
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        ordered.append(path)
    return ordered


def is_generated_source_path(path: Path) -> bool:
    path_posix = path.as_posix()
    return "/ghidra_autogen/" in path_posix or "/autogen/stubs/" in path_posix
