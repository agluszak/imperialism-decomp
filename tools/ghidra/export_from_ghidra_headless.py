#!/usr/bin/env python3
"""Headless symbol export for Imperialism Ghidra project.

This script is pinned to Ghidra 12.0.2 PUBLIC.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

EXPECTED_GHIDRA_VERSION = "12.0.2"
EXPECTED_GHIDRA_RELEASE = "PUBLIC"


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
        default=os.getenv("GHIDRA_PROGRAM_NAME", "Imperialism.exe"),
        help="Program name inside project",
    )
    parser.add_argument(
        "--output-dir",
        default=os.getenv("OUTPUT_DIR", str(repo_root / "config")),
        help="Output directory for symbols.ghidra.txt and symbols.csv",
    )
    return parser.parse_args()


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
        raise RuntimeError(
            f"Could not read version/release from {props_path}"
        )
    return version, release


def resolve_pyghidra_run(ghidra_install_dir: Path) -> Path:
    support_dir = ghidra_install_dir / "support"
    candidates = [
        support_dir / "pyghidraRun",
        support_dir / "pyghidraRun.bat",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(
        f"pyghidraRun launcher not found in {support_dir}"
    )


def build_pyghidra_cmd(
    pyghidra_run: Path,
    project_dir: Path,
    project_name: str,
    program_name: str,
    script_path: Path,
    post_script: str,
    output_file: Path,
) -> list[str]:
    cmd = [
        str(pyghidra_run),
        "-H",
        str(project_dir),
        project_name,
        "-process",
        program_name,
        "-scriptPath",
        str(script_path),
        "-postScript",
        post_script,
        str(output_file),
    ]
    if pyghidra_run.suffix.lower() == ".bat":
        return ["cmd", "/c", *cmd]
    return cmd


def require(value: str | None, name: str) -> str:
    if value:
        return value
    raise ValueError(
        f"Missing required argument: {name}. "
        f"You can also set env var {name.upper().replace('-', '_')}."
    )


def run_export(
    pyghidra_run: Path,
    project_dir: Path,
    project_name: str,
    program_name: str,
    script_dir: Path,
    post_script: str,
    output_file: Path,
) -> None:
    cmd = build_pyghidra_cmd(
        pyghidra_run=pyghidra_run,
        project_dir=project_dir,
        project_name=project_name,
        program_name=program_name,
        script_path=script_dir,
        post_script=post_script,
        output_file=output_file,
    )
    env = build_pyghidra_env()
    subprocess.run(cmd, check=True, env=env)


def build_pyghidra_env() -> dict[str, str]:
    """Avoid leaking uv/venv context into pyghidraRun.

    pyghidraRun chooses the "active virtual environment" when VIRTUAL_ENV is set,
    which can trigger interactive install prompts in non-TTY contexts.
    """
    env = dict(os.environ)
    venv = env.pop("VIRTUAL_ENV", None)
    env.pop("UV_ACTIVE", None)
    env.pop("UV_PROJECT_ENVIRONMENT", None)
    if venv:
        venv_bin = Path(venv) / ("Scripts" if os.name == "nt" else "bin")
        current_path = env.get("PATH", "")
        parts = [p for p in current_path.split(os.pathsep) if p]
        filtered = [p for p in parts if Path(p).resolve() != venv_bin.resolve()]
        env["PATH"] = os.pathsep.join(filtered)
    return env


def main() -> int:
    try:
        args = parse_args()
        ghidra_install_dir = Path(require(args.ghidra_install_dir, "--ghidra-install-dir"))
        ghidra_project_dir = Path(require(args.ghidra_project_dir, "--ghidra-project-dir"))
        ghidra_project_name = require(args.ghidra_project_name, "--ghidra-project-name")
        ghidra_program_name = args.ghidra_program_name
        output_dir = Path(args.output_dir)

        actual_version, actual_release = read_ghidra_props(ghidra_install_dir)
        if (
            actual_version != EXPECTED_GHIDRA_VERSION
            or actual_release != EXPECTED_GHIDRA_RELEASE
        ):
            raise RuntimeError(
                f"Unsupported Ghidra runtime: {actual_version} {actual_release}. "
                f"Expected {EXPECTED_GHIDRA_VERSION} {EXPECTED_GHIDRA_RELEASE}."
            )

        pyghidra_run = resolve_pyghidra_run(ghidra_install_dir)
        script_dir = Path(__file__).resolve().parent

        output_dir.mkdir(parents=True, exist_ok=True)
        symbols_txt = output_dir / "symbols.ghidra.txt"
        symbols_csv = output_dir / "symbols.csv"

        print(f"Exporting user-defined symbols to {symbols_txt}")
        run_export(
            pyghidra_run=pyghidra_run,
            project_dir=ghidra_project_dir,
            project_name=ghidra_project_name,
            program_name=ghidra_program_name,
            script_dir=script_dir,
            post_script="ExportUserSymbols_GhidraImport.py",
            output_file=symbols_txt,
        )

        print(f"Exporting reccmp CSV to {symbols_csv}")
        run_export(
            pyghidra_run=pyghidra_run,
            project_dir=ghidra_project_dir,
            project_name=ghidra_project_name,
            program_name=ghidra_program_name,
            script_dir=script_dir,
            post_script="ExportReccmpCsv_SmartSizes.py",
            output_file=symbols_csv,
        )

        print("Done.")
        print(f"  {symbols_txt}")
        print(f"  {symbols_csv}")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
