#!/usr/bin/env python3
"""Run one compiled semantic test in the instrumented Imperialism executable."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"


def retail_game_dir() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY to a complete retail installation")
    game_dir = Path(original).resolve().parent
    if not (game_dir / "Data").is_dir():
        raise SystemExit(f"Missing {game_dir / 'Data'}")
    return game_dir


def windows_path(path: Path) -> str:
    result = subprocess.run(
        ["winepath", "-w", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def run_test(name: str, timeout: float) -> int:
    executable = BUILD_DIR / "Imperialism.exe"
    if not executable.is_file():
        raise SystemExit(f"Missing {executable}; run `just runtime-test-build` first")

    result_dir = BUILD_DIR / "runtime-results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{name}.json"
    result_path.unlink(missing_ok=True)

    environment = dict(os.environ)
    environment["IMPERIALISM_RUNTIME_TEST"] = name
    environment["IMPERIALISM_RUNTIME_TEST_RESULT"] = windows_path(result_path)
    environment["WINEDEBUG"] = environment.get("WINEDEBUG", "-all")

    try:
        completed = subprocess.run(
            ["wine", str(executable)],
            cwd=retail_game_dir(),
            env=environment,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"runtime test timed out after {timeout:g}s") from error

    if not result_path.is_file():
        raise SystemExit(
            f"runtime test exited with code {completed.returncode} without writing {result_path}"
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2, sort_keys=True))
    if completed.returncode != 0:
        print(f"Wine process exited with code {completed.returncode}", file=sys.stderr)
        return 1
    return 0 if result.get("status") == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", default="boot_managers")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    return run_test(args.name, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
