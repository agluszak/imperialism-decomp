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
import sys
import time

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
sys.path.insert(0, str(REPO_ROOT))

from tools.runtime.artifacts import prune_old_run_dirs
from tools.runtime.catalog import (
    FIXTURES,
    find_test,
    missing_required_oracles,
    record_missing_oracles,
)
from tools.runtime.oracles.map import apply_map_oracle
from tools.runtime.protocol import read_json_file, validate_result
from tools.runtime.oracles.ui import apply_ui_oracle
from tools.runtime.session import execute_run


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
            require_fixtures = getattr(args, "require_fixtures", False)
            skipped = {
                "format_version": 1,
                "name": name,
                "status": "failed" if require_fixtures else "skipped",
                "failure": (
                    f"missing local save fixture {fixture}; place a retail-derived "
                    "save there (never committed) to enable this test"
                ),
            }
            serialized = json.dumps(skipped, indent=2, sort_keys=True) + "\n"
            (result_dir / f"{name}.json").write_text(serialized, encoding="utf-8")
            print(serialized, end="")
            return 1 if require_fixtures else 0
    run_id = f"{name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = result_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Attaching gdb costs ~4.5 s of the ~10 s a test takes, measured with the phase
    # timings in host["phase_seconds"]: launch drops from 8.4 s to 3.9 s without it.
    # That is paid on every test, including the ones that pass, to collect crash
    # classification that only failures need -- so the first attempt runs bare and a
    # failure is retried under the debugger, mirroring how --rerun-seh already works.
    # --gdb forces the debugger on the first attempt for interactive debugging.
    debugger_first = getattr(args, "gdb", False) and not args.no_gdb
    host = execute_run(
        name=name,
        run_dir=run_dir,
        seed=args.seed,
        timeout=args.timeout,
        phase_timeout_ms=args.phase_timeout_ms,
        winedebug=None,
        wine_log_name="wine.log",
        fixture=fixture,
        use_gdb=debugger_first,
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
            record_missing_oracles(
                result,
                missing_required_oracles(test_spec, result),
                fallback_failure=host["classification"],
            )

    failed = result.get("status") != "passed" or host["classification"] is not None
    if failed and not debugger_first and not args.no_gdb:
        gdb_run_dir = run_dir / "gdb-rerun"
        gdb_run_dir.mkdir(exist_ok=True)
        gdb_host = execute_run(
            name=name,
            run_dir=gdb_run_dir,
            seed=args.seed,
            timeout=args.timeout,
            phase_timeout_ms=args.phase_timeout_ms,
            winedebug=None,
            wine_log_name="wine.log",
            fixture=fixture,
            use_gdb=True,
        )
        gdb_result = read_json_file(gdb_run_dir / "result.json")
        if gdb_result is not None:
            try:
                validate_result(gdb_result, name, args.seed)
                apply_ui_oracle(gdb_result)
                apply_map_oracle(gdb_result, name, args.seed)
                if test_spec is not None:
                    record_missing_oracles(
                        gdb_result,
                        missing_required_oracles(test_spec, gdb_result),
                        fallback_failure=gdb_host["classification"],
                    )
                # Keep the debugger run: it carries the backtrace and classification the
                # bare run could not produce. Note when the failure did not reproduce.
                gdb_result["bare_run_failure"] = result.get("failure")
                result, host = gdb_result, gdb_host
            except ValueError:
                host["gdb_rerun"] = gdb_host
        else:
            host["gdb_rerun"] = gdb_host
        failed = result.get("status") != "passed" or host["classification"] is not None

    if failed and args.rerun_seh:
        seh_run_dir = run_dir / "seh-rerun"
        seh_run_dir.mkdir()
        host["seh_rerun"] = execute_run(
            name=name,
            run_dir=seh_run_dir,
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
    if host["inferior_exit_code"] not in {None, 0}:
        print(
            f"Inferior exited with code {host['inferior_exit_code']}", file=sys.stderr
        )
        return 1
    return 0 if result.get("status") == "passed" else 1


def main() -> int:
    from tools.runtime.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
