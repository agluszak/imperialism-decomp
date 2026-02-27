from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_GHIDRA_DIR = Path(
    Path.home() / "Downloads" / "ghidra_12.0.2_PUBLIC_20260129" / "ghidra_12.0.2_PUBLIC"
)
DEFAULT_PROJECT_NAME = "imperialism-decomp"
DEFAULT_PROGRAM_PATH = "/Imperialism.exe"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_project_root() -> str:
    return str(repo_root())


def resolve_project_root(project_root: str | Path | None) -> Path:
    if project_root is None:
        return repo_root().resolve()
    return Path(project_root).resolve()


@dataclass(frozen=True)
class RuntimeConfig:
    ghidra_dir: Path
    project_root: Path
    project_name: str
    program_path: str



def get_runtime_config(project_root: Path | None = None) -> RuntimeConfig:
    root = project_root or Path(os.getenv("IMPK_PROJECT_ROOT", repo_root())).resolve()
    return RuntimeConfig(
        ghidra_dir=Path(os.getenv("IMPK_GHIDRA_DIR", str(DEFAULT_GHIDRA_DIR))).resolve(),
        project_root=root,
        project_name=os.getenv("IMPK_PROJECT_NAME", DEFAULT_PROJECT_NAME),
        program_path=os.getenv("IMPK_PROGRAM_PATH", DEFAULT_PROGRAM_PATH),
    )
