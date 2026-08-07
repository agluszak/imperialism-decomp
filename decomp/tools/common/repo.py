#!/usr/bin/env python3
"""Repository path helpers for tooling scripts."""

from __future__ import annotations

import subprocess
from pathlib import Path


def repo_root_from_file(file_path: str | Path, levels_up: int = 2) -> Path:
    return Path(file_path).resolve().parents[levels_up]


def resolve_repo_path(repo_root: Path, path_value: str | Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path.resolve()
    return (repo_root / path).resolve()


def normalize_repo_relative_path(path: Path, repo_root: Path) -> str:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
        return rel.as_posix()
    except ValueError:
        return path.resolve().as_posix()


def dirty_tracked_paths(repo_root: Path, paths: list[str]) -> list[str]:
    """Repo-relative paths under `paths` with uncommitted changes (tracked or not).

    Returns an empty list if `repo_root` isn't a git checkout or `git` isn't
    available — callers use this for an advisory staleness hint, not a hard check.
    """
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--", *paths],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    return [line[3:].strip() for line in result.stdout.splitlines() if line.strip()]
