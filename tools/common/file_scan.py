#!/usr/bin/env python3
"""Shared source file scanning helpers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

CPP_HEADER_PATTERNS = ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx")

# Nested git worktrees created by the Agent tool's isolation:"worktree" option live
# under .claude/worktrees/<id>/ and contain a full checkout of every source file with
# the same // FUNCTION:/// VTABLE:/// GLOBAL: markers. A repo-wide source scan that
# descends into them registers every marker address twice, corrupting duplicate-address
# dedup (see bd imperialism-decomp-idi). Bounded roots (src/, include/) never reach them,
# but exclude defensively so a scan rooted at the repo root stays correct too.
#
# Caveat: when the SCAN ITSELF is rooted inside a `.claude/worktrees/<id>/` checkout
# (an agent doing its own work isolated in such a worktree, as opposed to a scan from
# a normal checkout recursing INTO a nested one), every resolved path's ABSOLUTE
# ancestry already contains ".claude" harmlessly — that is not the duplicate-checkout
# case this guard exists for. `is_excluded_scan_path` takes the scan roots so it can
# check only path components found AFTER a root (i.e. genuinely reached via
# recursion), not the root's own ancestry; falls back to whole-path checking when no
# roots are given (back-compat for callers that check a single path in isolation).
_EXCLUDED_PATH_PARTS = (".claude",)


def is_excluded_scan_path(path: Path, roots: Iterable[Path] = ()) -> bool:
    """True for paths under runtime-state dirs (e.g. .claude/worktrees/) that must never
    be treated as canonical source during a repo-wide scan."""
    resolved = path.resolve()
    for root in roots:
        try:
            rel_parts = resolved.relative_to(root.resolve()).parts
        except ValueError:
            continue
        return any(part in _EXCLUDED_PATH_PARTS for part in rel_parts)
    return any(part in _EXCLUDED_PATH_PARTS for part in resolved.parts)

# Hand-owned headers carry a marked, auto-generated reference block (inserted by a
# now-retired generator) inside them. Its slot table embeds raw provisional Ghidra
# names that can incidentally match banned-pattern regexes (bridge names, etc.).
# Source-policy gates that scan for *hand-written* anti-patterns must skip these
# blocks.
_GENERATED_BLOCK_RE = re.compile(
    r"^[ \t]*//[ \t]*===[ \t]*BEGIN GENERATED \(\w+\).*?^[ \t]*//[ \t]*===[ \t]*END GENERATED \(\w+\)[ \t]*===[ \t]*$",
    re.DOTALL | re.MULTILINE,
)


def strip_generated_blocks(text: str) -> str:
    """Blank out GENERATED reference blocks (keeping line count) before pattern scans."""
    def _blank(match: re.Match[str]) -> str:
        return "\n".join("" for _ in match.group(0).splitlines())

    return _GENERATED_BLOCK_RE.sub(_blank, text)


def iter_files(paths: Iterable[str], patterns: Iterable[str] = CPP_HEADER_PATTERNS) -> list[Path]:
    # Track which caller-supplied root each file came from, so exclusion is checked
    # relative to that root (see is_excluded_scan_path) rather than against the full
    # absolute path -- the caller's own checkout may legitimately sit under a
    # `.claude/worktrees/<id>/` directory.
    files: list[tuple[Path, Path]] = []
    roots: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_file():
            files.append((path, path.parent))
            continue
        if path.is_dir():
            roots.append(path)
            for pattern in patterns:
                for found in sorted(path.rglob(pattern)):
                    files.append((found, path))

    seen: set[Path] = set()
    ordered: list[Path] = []
    for path, root in sorted(files, key=lambda pair: pair[0]):
        if is_excluded_scan_path(path, [root]):
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        ordered.append(path)
    return ordered


def is_generated_source_path(path: Path) -> bool:
    path_posix = path.as_posix()
    return "/ghidra_autogen/" in path_posix or "/autogen/stubs/" in path_posix
