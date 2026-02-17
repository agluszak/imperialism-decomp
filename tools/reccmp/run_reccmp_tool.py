#!/usr/bin/env python3
"""Run a reccmp CLI tool from the dedicated .venv-reccmp environment."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

RECCMP_VENV_DIR = ".venv-reccmp"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cwd",
        default=None,
        help="Working directory for the reccmp tool process (default: repo root).",
    )
    parser.add_argument("tool", help="reccmp executable name (e.g. reccmp-project)")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments forwarded to the tool")
    return parser.parse_args()


def venv_bin_path(repo_root: Path, name: str) -> Path:
    if sys.platform == "win32":
        return repo_root / RECCMP_VENV_DIR / "Scripts" / f"{name}.exe"
    return repo_root / RECCMP_VENV_DIR / "bin" / name


def main() -> int:
    try:
        args = parse_args()
        repo_root = Path(__file__).resolve().parents[2]
        tool_path = venv_bin_path(repo_root, args.tool)
        if not tool_path.is_file():
            raise FileNotFoundError(
                f"Missing {tool_path}. Run: uv run python tools/reccmp/bootstrap_reccmp.py"
            )

        cmd = [str(tool_path)]
        if args.args:
            cmd.extend(args.args)
        run_cwd = Path(args.cwd).resolve() if args.cwd else repo_root
        subprocess.run(cmd, cwd=run_cwd, check=True)
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
