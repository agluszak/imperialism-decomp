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
import copy
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
from tools.runtime.oracles.map import evaluate_map_oracle
from tools.runtime.protocol import read_json_file, validate_result
from tools.runtime.oracles.ui import evaluate_ui_oracle
from tools.runtime.session import execute_run


def fixture_directory() -> Path:
    override = os.environ.get("IMPERIALISM_SAVE_FIXTURES")
    if override:
        return Path(override)
    return REPO_ROOT / "tests" / "runtime" / "fixtures"


def _record_failure(result: dict, summary: str) -> None:
    if result.get("status") == "passed":
        result["status"] = "failed"
        result["failure"] = summary
        return
    if not result.get("failure"):
        result["failure"] = summary
        return
    if result.get("failure") != summary:
        result["secondary_failures"] = [*result.get("secondary_failures", []), summary]


def _process_attempt(
    *, name: str, seed: int, run_dir: Path, host: dict, kind: str, authoritative: bool
) -> tuple[dict, dict]:
    """Validate and enrich one attempt without losing its raw native/host evidence."""
    raw_native = read_json_file(run_dir / "result.json")
    if raw_native is None:
        result = {
            "format_version": 1,
            "name": name,
            "seed": seed,
            "status": "failed",
            "failure": host.get("classification") or "missing result file",
        }
    else:
        result = copy.deepcopy(raw_native)
        try:
            validate_result(result, name, seed)
        except ValueError as error:
            result = {
                "format_version": 1,
                "name": name,
                "seed": seed,
                "status": "failed",
                "failure": f"invalid native result: {error}",
                "invalid_native_result": raw_native,
            }

    oracle_reports: dict[str, dict] = {}
    evaluators = (
        ("ui", lambda: evaluate_ui_oracle(result)),
        ("map", lambda: evaluate_map_oracle(result, name, seed)),
    )
    for oracle_name, evaluator in evaluators:
        try:
            report = evaluator()
        except Exception as error:
            report = {
                "status": "error",
                "error": f"{type(error).__name__}: {error}",
            }
        if report is None:
            continue
        oracle_reports[oracle_name] = report
        result[f"{oracle_name}_oracle"] = report
        if report.get("status") == "failed":
            _record_failure(result, f"{oracle_name} oracle mismatch")
        elif report.get("status") == "error":
            _record_failure(result, f"{oracle_name} oracle error: {report['error']}")

    test_spec = find_test(name)
    if test_spec is not None:
        record_missing_oracles(
            result,
            missing_required_oracles(test_spec, result),
            fallback_failure=host.get("classification"),
        )
    if host.get("classification") is not None:
        _record_failure(result, str(host["classification"]))

    run_dir.mkdir(parents=True, exist_ok=True)
    if raw_native is not None:
        (run_dir / "native-result.json").write_text(
            json.dumps(raw_native, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (run_dir / "run.json").write_text(
        json.dumps(host, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_dir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    attempt = {
        "kind": kind,
        "authoritative": authoritative,
        "run_dir": str(run_dir),
        "status": result.get("status"),
        "classification": host.get("classification"),
        "host": copy.deepcopy(host),
        "native": copy.deepcopy(raw_native),
        "oracles": oracle_reports,
    }
    return result, attempt


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
    primary_host = execute_run(
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
    primary_host.update(
        {
            "run_id": run_id,
            "run_dir": str(run_dir),
            "seed": args.seed,
            "timeout_seconds": args.timeout,
            "phase_timeout_ms": args.phase_timeout_ms,
        }
    )

    result, primary_attempt = _process_attempt(
        name=name,
        seed=args.seed,
        run_dir=run_dir,
        host=primary_host,
        kind="primary_gdb" if debugger_first else "primary_wine",
        authoritative=True,
    )
    attempts = [primary_attempt]
    failed = result.get("status") != "passed" or primary_host["classification"] is not None
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
        gdb_result, gdb_attempt = _process_attempt(
            name=name,
            seed=args.seed,
            run_dir=gdb_run_dir,
            host=gdb_host,
            kind="diagnostic_gdb",
            authoritative=False,
        )
        attempts.append(gdb_attempt)
        if gdb_result.get("status") == "passed" and gdb_host.get("classification") is None:
            result["classification"] = "debugger_sensitive_non_reproduction"
        result["diagnostic_gdb"] = {
            "status": gdb_result.get("status"),
            "classification": gdb_host.get("classification"),
            "run_dir": str(gdb_run_dir),
        }

    if failed and args.rerun_seh:
        seh_run_dir = run_dir / "seh-rerun"
        seh_run_dir.mkdir()
        seh_host = execute_run(
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
        seh_result, seh_attempt = _process_attempt(
            name=name,
            seed=args.seed,
            run_dir=seh_run_dir,
            host=seh_host,
            kind="diagnostic_seh",
            authoritative=False,
        )
        attempts.append(seh_attempt)
        result["diagnostic_seh"] = {
            "status": seh_result.get("status"),
            "classification": seh_host.get("classification"),
            "run_dir": str(seh_run_dir),
        }

    result["host"] = primary_host
    result["attempts"] = attempts
    result_path = run_dir / "result.json"
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    result_path.write_text(serialized, encoding="utf-8")
    # Canonical latest-result location, kept for existing consumers.
    (result_dir / f"{name}.json").write_text(serialized, encoding="utf-8")
    prune_old_run_dirs(result_dir, name)
    print(serialized, end="")
    if primary_host["classification"] is not None:
        print(
            f"runtime test classified as {primary_host['classification']}", file=sys.stderr
        )
        return 1
    if primary_host["inferior_exit_code"] not in {None, 0}:
        print(
            f"Inferior exited with code {primary_host['inferior_exit_code']}", file=sys.stderr
        )
        return 1
    return 0 if result.get("status") == "passed" else 1


def main() -> int:
    from tools.runtime.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
