#!/usr/bin/env python3
"""Compatibility entrypoint for the typed semantic runtime runner."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
sys.path.insert(0, str(REPO_ROOT))

from tools.runtime.runner import (
    RunRequest,
    RunnerDependencies,
    RuntimeRunner,
    format_console_summary,
)


def fixture_directory() -> Path:
    override = os.environ.get("IMPERIALISM_SAVE_FIXTURES")
    return Path(override) if override else REPO_ROOT / "tests" / "runtime" / "fixtures"


def run_test(
    args: argparse.Namespace, dependencies: RunnerDependencies | None = None
) -> int:
    request = RunRequest(
        name=args.name,
        seed=getattr(args, "seed", 1),
        timeout_seconds=getattr(args, "timeout", 300.0),
        phase_timeout_ms=getattr(args, "phase_timeout_ms", 60_000),
        rerun_seh=getattr(args, "rerun_seh", False),
        gdb_first=getattr(args, "gdb", False),
        no_gdb=getattr(args, "no_gdb", False),
        require_fixtures=getattr(args, "require_fixtures", False),
    )
    outcome = RuntimeRunner(
        BUILD_DIR / "runtime-results", fixture_directory(), dependencies
    ).run(request)
    serialized = json.dumps(outcome.result, indent=2, sort_keys=True) + "\n"
    print(serialized, end="")
    print(format_console_summary(outcome.result), file=sys.stderr)
    return outcome.exit_code


def main() -> int:
    from tools.runtime.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
