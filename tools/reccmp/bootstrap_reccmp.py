#!/usr/bin/env python3
"""Bootstrap reccmp in a dedicated virtualenv (.venv-reccmp)."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

RECCMP_VENV_DIR = ".venv-reccmp"
RECCMP_GIT_SOURCE = "git+https://github.com/isledecomp/reccmp.git@master"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--original-binary",
        default=os.getenv("ORIGINAL_BINARY"),
        help="Path to original Imperialism.exe for `reccmp-project create`",
    )
    return parser.parse_args()


def run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, check=True, cwd=cwd)


def venv_bin_path(repo_root: Path, name: str) -> Path:
    if sys.platform == "win32":
        return repo_root / RECCMP_VENV_DIR / "Scripts" / f"{name}.exe"
    return repo_root / RECCMP_VENV_DIR / "bin" / name


def main() -> int:
    try:
        repo_root = Path(__file__).resolve().parents[2]
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("uv is not installed or not in PATH.")

        args = parse_args()
        run([uv, "venv", RECCMP_VENV_DIR], cwd=repo_root)

        venv_python = venv_bin_path(repo_root, "python")
        if not venv_python.is_file():
            raise FileNotFoundError(f"Missing Python in {RECCMP_VENV_DIR}: {venv_python}")

        run(
            [
                uv,
                "pip",
                "install",
                "--python",
                str(venv_python),
                RECCMP_GIT_SOURCE,
            ],
            cwd=repo_root,
        )

        reccmp_project = venv_bin_path(repo_root, "reccmp-project")
        if not reccmp_project.is_file():
            raise FileNotFoundError(
                f"Missing reccmp-project in {RECCMP_VENV_DIR}: {reccmp_project}"
            )

        if args.original_binary:
            original = Path(args.original_binary)
            if not original.is_file():
                raise FileNotFoundError(f"Original binary not found: {original}")
            project_yml = repo_root / "reccmp-project.yml"
            if not project_yml.is_file():
                run(
                    [
                        str(reccmp_project),
                        "create",
                        "--originals",
                        str(original),
                        "--scm",
                    ],
                    cwd=repo_root,
                )
                print("Created reccmp-project.yml and reccmp-user.yml")
            else:
                print("reccmp-project.yml already exists; skipping create step.")
        else:
            print("No --original-binary provided; skipping `reccmp-project create`.")

        print("Done.")
        print("Next:")
        print("  uv run python tools/reccmp/run_reccmp_tool.py reccmp-project --help")
        print("  uv run python tools/reccmp/run_reccmp_tool.py reccmp-reccmp --help")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
