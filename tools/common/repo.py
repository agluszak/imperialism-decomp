#!/usr/bin/env python3
"""Repository path helpers for tooling scripts."""

from __future__ import annotations

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
