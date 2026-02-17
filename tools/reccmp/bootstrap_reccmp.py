#!/usr/bin/env python3
"""Bootstrap reccmp via uv + pyproject.toml."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


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


def main() -> int:
    try:
        repo_root = Path(__file__).resolve().parents[2]
        pyproject = repo_root / "pyproject.toml"
        if not pyproject.is_file():
            raise FileNotFoundError(f"Missing {pyproject}")

        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("uv is not installed or not in PATH.")

        args = parse_args()
        run([uv, "sync", "--group", "reccmp"], cwd=repo_root)

        if args.original_binary:
            original = Path(args.original_binary)
            if not original.is_file():
                raise FileNotFoundError(f"Original binary not found: {original}")
            project_yml = repo_root / "reccmp-project.yml"
            if not project_yml.is_file():
                run(
                    [
                        uv,
                        "run",
                        "--group",
                        "reccmp",
                        "reccmp-project",
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
        print("  uv run --group reccmp reccmp-project --help")
        print("  uv run --group reccmp reccmp-reccmp --help")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
