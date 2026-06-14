#!/usr/bin/env python3
"""Shared pyghidra bootstrap for all `tools/ghidra/*` entrypoints.

Centralizes what every Ghidra tool used to copy-paste: resolving the vendored
project/program env, enforcing that the installed Ghidra and pyghidra runtime match
what the repo expects (`ghidra.toml`), starting pyghidra, and opening the project /
program. Routing every tool through here means the version check runs eagerly on
*any* Ghidra command, not only `just sync-ghidra`.

Typical read-only use:

    from tools.common import ghidra_env

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    try:
        ...
    finally:
        program.release(consumer)
        project.close()
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_CONFIG_PATH = REPO_ROOT / "ghidra.toml"

# pyghidra runtime pin (kept in lockstep with the Ghidra version in ghidra.toml).
EXPECTED_PYGHIDRA_VERSION = "3.1.0"

DEFAULT_PROJECT_DIR = REPO_ROOT / "vendor" / "ghidra"
DEFAULT_PROJECT_NAME = "imperialism-decomp"
DEFAULT_PROGRAM_NAME = "Imperialism.exe"


def project_location() -> str:
    return os.getenv("GHIDRA_PROJECT_DIR", str(DEFAULT_PROJECT_DIR))


def project_name() -> str:
    return os.getenv("GHIDRA_PROJECT_NAME", DEFAULT_PROJECT_NAME)


def program_name() -> str:
    return os.getenv("GHIDRA_PROGRAM_NAME", DEFAULT_PROGRAM_NAME)


def install_dir() -> Path | None:
    value = os.getenv("GHIDRA_INSTALL_DIR")
    return Path(value) if value else None


def _read_repo_config() -> dict:
    if not REPO_CONFIG_PATH.is_file():
        raise FileNotFoundError(f"Missing {REPO_CONFIG_PATH}")
    with REPO_CONFIG_PATH.open("rb") as fd:
        return tomllib.load(fd)


def read_ghidra_props(ghidra_install_dir: Path) -> tuple[str, str]:
    """Return (version, release) from the installed Ghidra's application.properties."""
    props_path = ghidra_install_dir / "Ghidra" / "application.properties"
    if not props_path.is_file():
        raise FileNotFoundError(f"Missing Ghidra application.properties: {props_path}")

    version = None
    release = None
    for raw in props_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.startswith("application.version="):
            version = line.split("=", 1)[1].strip()
        elif line.startswith("application.release.name="):
            release = line.split("=", 1)[1].strip()

    if not version or not release:
        raise RuntimeError(f"Could not read version/release from {props_path}")
    return version, release


def expected_versions() -> tuple[str, str]:
    """Return (version, release) the repo expects, from ghidra.toml."""
    gh_cfg = _read_repo_config().get("ghidra", {})
    version = str(gh_cfg.get("version", "")).strip()
    release = str(gh_cfg.get("release", "")).strip()
    if not version or not release:
        raise RuntimeError(f"{REPO_CONFIG_PATH} must define [ghidra].version and [ghidra].release")
    return version, release


def enforce_versions(ghidra_install_dir: Path | None) -> None:
    """Fail fast if the pyghidra runtime or installed Ghidra differ from ghidra.toml."""
    import pyghidra

    pyghidra_version = getattr(pyghidra, "__version__", "unknown")
    if pyghidra_version != EXPECTED_PYGHIDRA_VERSION:
        raise RuntimeError(
            f"Unsupported pyghidra runtime: {pyghidra_version}. "
            f"Expected {EXPECTED_PYGHIDRA_VERSION}."
        )

    expected_version, expected_release = expected_versions()

    if ghidra_install_dir is None:
        raise RuntimeError(
            "GHIDRA_INSTALL_DIR is not set; cannot verify the Ghidra runtime. "
            "Set it in .env."
        )
    actual_version, actual_release = read_ghidra_props(ghidra_install_dir)
    if actual_version != expected_version or actual_release != expected_release:
        raise RuntimeError(
            f"Unsupported Ghidra runtime: {actual_version} {actual_release}. "
            f"Expected {expected_version} {expected_release} (per {REPO_CONFIG_PATH.name}). "
            f"Update ghidra.toml or point GHIDRA_INSTALL_DIR at the matching install."
        )


def start(ghidra_install_dir: Path | None = None) -> None:
    """Enforce versions, then start pyghidra."""
    import pyghidra

    resolved = Path(ghidra_install_dir) if ghidra_install_dir else install_dir()
    enforce_versions(resolved)
    pyghidra.start(install_dir=resolved)


def open_project(create: bool = False):
    """Start pyghidra (with the eager version check) and open the vendored project."""
    import pyghidra

    start()
    return pyghidra.open_project(project_location(), project_name(), create=create)


def open_program(project, writable: bool = False):
    """Open the program inside ``project``; returns (consumer, program).

    Caller is responsible for ``program.release(consumer)`` and ``project.close()``.
    """
    import pyghidra
    from java.lang import Object as JavaObject

    consumer = JavaObject()
    name = program_name()
    program_path = name if name.startswith("/") else f"/{name}"
    domain_file = project.getProjectData().getFile(program_path)
    if domain_file is None:
        raise FileNotFoundError(f'Program "{name}" not found in project "{project_name()}".')
    if writable:
        program = domain_file.getDomainObject(consumer, True, False, pyghidra.task_monitor())
    else:
        program = domain_file.getReadOnlyDomainObject(consumer, -1, pyghidra.task_monitor())
    return consumer, program
