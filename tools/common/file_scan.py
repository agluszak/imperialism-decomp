#!/usr/bin/env python3
"""Shared source file scanning helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


CPP_HEADER_PATTERNS = ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx")


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
