#!/usr/bin/env python3
"""Single-entry export sync using pyghidra (in-process, no pyghidraRun subprocess)."""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

import pyghidra

REPO_CONFIG_PATH = "ghidra.toml"
EXPECTED_PYGHIDRA_VERSION = "3.0.2"


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ghidra-install-dir",
        default=os.getenv("GHIDRA_INSTALL_DIR"),
        help="Path to ghidra_12.0.2_PUBLIC installation directory",
    )
    parser.add_argument(
        "--ghidra-project-dir",
        default=os.getenv("GHIDRA_PROJECT_DIR"),
        help="Directory containing the Ghidra project",
    )
    parser.add_argument(
        "--ghidra-project-name",
        default=os.getenv("GHIDRA_PROJECT_NAME"),
        help="Ghidra project name (without .gpr suffix)",
    )
    parser.add_argument(
        "--ghidra-program-name",
        default=os.getenv("GHIDRA_PROGRAM_NAME"),
        help="Program name inside project (defaults from ghidra.toml)",
    )
    parser.add_argument(
        "--output-dir",
        default=os.getenv("OUTPUT_DIR", str(repo_root / "config")),
        help="Output directory for symbols.ghidra.txt and symbols.csv",
    )
    parser.add_argument(
        "--decomp-output-dir",
        default=os.getenv("DECOMP_OUTPUT_DIR", str(repo_root / "src" / "ghidra_autogen")),
        help="Output directory for split decompiled function bodies",
    )
    parser.add_argument(
        "--types-output-dir",
        default=os.getenv("TYPES_OUTPUT_DIR", str(repo_root / "include" / "ghidra_autogen")),
        help="Output directory for split datatype headers",
    )
    parser.add_argument(
        "--decomp-max-functions-per-file",
        type=int,
        default=None,
        help="Maximum number of functions per generated decompiled .cpp file",
    )
    return parser.parse_args()


def require(value: str | None, name: str) -> str:
    if value:
        return value
    raise ValueError(
        f"Missing required argument: {name}. You can also set env var {name.upper().replace('-', '_')}."
    )


def read_repo_config(repo_root: Path) -> dict:
    config_path = repo_root / REPO_CONFIG_PATH
    if not config_path.is_file():
        raise FileNotFoundError(f"Missing {config_path}")
    with config_path.open("rb") as fd:
        return tomllib.load(fd)


def read_ghidra_props(ghidra_install_dir: Path) -> tuple[str, str]:
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


def main() -> int:
    try:
        repo_root = Path(__file__).resolve().parents[2]
        args = parse_args()
        cfg = read_repo_config(repo_root)

        gh_cfg = cfg.get("ghidra", {})
        exp_cfg = cfg.get("exports", {})
        expected_version = str(gh_cfg.get("version", "")).strip()
        expected_release = str(gh_cfg.get("release", "")).strip()
        default_program = str(gh_cfg.get("program_name", "Imperialism.exe")).strip()
        default_max_per_file = int(exp_cfg.get("decomp_max_functions_per_file", 250))

        if not expected_version or not expected_release:
            raise RuntimeError(
                f"{REPO_CONFIG_PATH} must define [ghidra].version and [ghidra].release"
            )

        pyghidra_version = getattr(pyghidra, "__version__", "unknown")
        if pyghidra_version != EXPECTED_PYGHIDRA_VERSION:
            raise RuntimeError(
                f"Unsupported pyghidra runtime: {pyghidra_version}. "
                f"Expected {EXPECTED_PYGHIDRA_VERSION}."
            )

        ghidra_install_dir = Path(require(args.ghidra_install_dir, "--ghidra-install-dir"))
        ghidra_project_dir = Path(require(args.ghidra_project_dir, "--ghidra-project-dir"))
        ghidra_project_name = require(args.ghidra_project_name, "--ghidra-project-name")
        ghidra_program_name = args.ghidra_program_name or default_program
        output_dir = Path(args.output_dir).resolve()
        decomp_output_dir = Path(args.decomp_output_dir).resolve()
        types_output_dir = Path(args.types_output_dir).resolve()
        max_per_file = (
            args.decomp_max_functions_per_file
            if args.decomp_max_functions_per_file is not None
            else default_max_per_file
        )

        actual_version, actual_release = read_ghidra_props(ghidra_install_dir)
        if actual_version != expected_version or actual_release != expected_release:
            raise RuntimeError(
                f"Unsupported Ghidra runtime: {actual_version} {actual_release}. "
                f"Expected {expected_version} {expected_release}."
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        decomp_output_dir.mkdir(parents=True, exist_ok=True)
        types_output_dir.mkdir(parents=True, exist_ok=True)

        symbols_txt = output_dir / "symbols.ghidra.txt"
        symbols_csv = output_dir / "symbols.csv"
        script_path = Path(__file__).resolve().parent / "SyncExports_Ghidra.py"
        if not script_path.is_file():
            raise FileNotFoundError(f"Missing script: {script_path}")

        script_args = [
            str(symbols_txt),
            str(symbols_csv),
            str(decomp_output_dir),
            str(types_output_dir),
            str(max_per_file),
            expected_version,
            expected_release,
        ]

        pyghidra.start(install_dir=ghidra_install_dir)
        project = pyghidra.open_project(ghidra_project_dir, ghidra_project_name, create=False)
        from java.lang import Object as JavaObject

        consumer = JavaObject()
        program = None
        try:
            program_path = (
                ghidra_program_name
                if ghidra_program_name.startswith("/")
                else f"/{ghidra_program_name}"
            )
            domain_file = project.getProjectData().getFile(program_path)
            if domain_file is None:
                raise FileNotFoundError(
                    f'Program "{ghidra_program_name}" not found in project "{ghidra_project_name}".'
                )
            program = domain_file.getReadOnlyDomainObject(
                consumer,
                -1,
                pyghidra.task_monitor(),
            )
            pyghidra.ghidra_script(
                script_path,
                project=project,
                program=program,
                script_args=script_args,
                echo_stdout=True,
                echo_stderr=True,
            )
        finally:
            if program is not None:
                program.release(consumer)
            project.close()

        print("Done.")
        print(f"  {symbols_txt}")
        print(f"  {symbols_csv}")
        print(f"  {decomp_output_dir}")
        print(f"  {types_output_dir}")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
