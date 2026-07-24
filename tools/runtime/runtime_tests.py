#!/usr/bin/env python3
"""Run one compiled semantic test in the instrumented Imperialism executable.

Each run is isolated in its own WINEPREFIX and produces a per-run bundle under
build-runtime-tests/runtime-results/<run-id>/ containing result.json, the final
heartbeat.json, wine.log, run.json (host metadata + failure classification) and,
on failure, a best-effort screenshot. Cleanup only ever touches the run's own
Wine server and game process — never other agents' sessions.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
sys.path.insert(0, str(REPO_ROOT))

from tools.workflow.ui_platform_diff import build_report
from tools.runtime.artifacts import prune_old_run_dirs
from tools.runtime.catalog import FIXTURES, find_test, missing_required_oracles
from tools.runtime.classification import (
    classify_exit,
    classify_poll,
    no_progress_budget_seconds,
)
from tools.runtime.oracles.map import apply_map_oracle, compare_map_state
from tools.runtime.protocol import read_json_file, validate_result
from tools.runtime.oracles.ui import apply_ui_oracle
from tools.runtime.session import execute_run

POLL_INTERVAL_SECONDS = 0.5


def fixture_directory() -> Path:
    override = os.environ.get("IMPERIALISM_SAVE_FIXTURES")
    if override:
        return Path(override)
    return REPO_ROOT / "tests" / "runtime" / "fixtures"


def run_test(args: argparse.Namespace) -> int:
    name = args.name
    result_dir = BUILD_DIR / "runtime-results"
    result_dir.mkdir(parents=True, exist_ok=True)

    fixture: Path | None = None
    if name in FIXTURES:
        fixture = fixture_directory() / FIXTURES[name]
        if not fixture.is_file():
            skipped = {
                "format_version": 1,
                "name": name,
                "status": "skipped",
                "failure": (
                    f"missing local save fixture {fixture}; place a retail-derived "
                    "save there (never committed) to enable this test"
                ),
            }
            serialized = json.dumps(skipped, indent=2, sort_keys=True) + "\n"
            (result_dir / f"{name}.json").write_text(serialized, encoding="utf-8")
            print(serialized, end="")
            return 0
    run_id = f"{name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = result_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    host = execute_run(
        name=name,
        run_dir=run_dir,
        seed=args.seed,
        timeout=args.timeout,
        phase_timeout_ms=args.phase_timeout_ms,
        winedebug=None,
        wine_log_name="wine.log",
        fixture=fixture,
        use_gdb=not args.no_gdb,
    )
    host.update(
        {
            "run_id": run_id,
            "run_dir": str(run_dir),
            "seed": args.seed,
            "timeout_seconds": args.timeout,
            "phase_timeout_ms": args.phase_timeout_ms,
        }
    )

    result_path = run_dir / "result.json"
    result = read_json_file(result_path)
    if result is None:
        result = {
            "format_version": 1,
            "name": name,
            "status": "failed",
            "failure": host["classification"] or "missing result file",
        }
    else:
        try:
            validate_result(result, name, args.seed)
        except ValueError as error:
            raise SystemExit(str(error)) from error
        try:
            apply_ui_oracle(result)
        except ValueError as error:
            raise SystemExit(str(error)) from error
        apply_map_oracle(result, name, args.seed)
        test_spec = find_test(name)
        if test_spec is not None:
            missing_oracles = missing_required_oracles(test_spec, result)
            if missing_oracles:
                result["status"] = "failed"
                result["failure"] = "missing required oracle(s): " + ", ".join(missing_oracles)

    failed = result.get("status") != "passed" or host["classification"] is not None
    if failed and args.rerun_seh:
        host["seh_rerun"] = execute_run(
            name=name,
            run_dir=run_dir,
            seed=args.seed,
            timeout=args.timeout,
            phase_timeout_ms=args.phase_timeout_ms,
            winedebug="+seh",
            wine_log_name="wine-seh.log",
            fixture=fixture,
            use_gdb=not args.no_gdb,
        )

    result["host"] = host
    (run_dir / "run.json").write_text(
        json.dumps(host, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    result_path.write_text(serialized, encoding="utf-8")
    # Canonical latest-result location, kept for existing consumers.
    (result_dir / f"{name}.json").write_text(serialized, encoding="utf-8")
    prune_old_run_dirs(result_dir, name)
    print(serialized, end="")
    if host["classification"] is not None:
        print(f"runtime test classified as {host['classification']}", file=sys.stderr)
        return 1
    if host["wine_exit"] != 0:
        print(f"Wine process exited with code {host['wine_exit']}", file=sys.stderr)
        return 1
    return 0 if result.get("status") == "passed" else 1


def main() -> int:
    from tools.runtime.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
