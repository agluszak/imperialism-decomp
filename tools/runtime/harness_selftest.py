"""Run the fast native harness contract executable without launching the game."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time

from tools.runtime.catalog import RuntimeTestSpec, apply_expected_failure
from tools.runtime.protocol import read_json_file, validate_result


def _windows_path(path: Path) -> str:
    return "Z:" + str(path.resolve()).replace("/", "\\")


def run_harness_selftest(
    spec: RuntimeTestSpec, seed: int, build_dir: Path, result_dir: Path
) -> int:
    executable = build_dir / "ImperialismRuntimeSelfTest.exe"
    if not executable.is_file():
        raise SystemExit(f"missing {executable}; run `just runtime-test-build` first")
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{spec.name}.json"
    result_path.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment.setdefault("WINEDEBUG", "-all")
    started = time.monotonic()
    completed = subprocess.run(
        [
            "wine",
            _windows_path(executable),
            _windows_path(result_path),
            spec.name,
            str(seed),
        ],
        cwd=build_dir,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    duration = time.monotonic() - started
    result = read_json_file(result_path)
    if result is None:
        result = {
            "format_version": 1,
            "name": spec.name,
            "seed": seed,
            "status": "failed",
            "failure": (
                "native harness self-test produced no result; "
                f"exit={completed.returncode} stderr={completed.stderr.strip()}"
            ),
        }
    else:
        try:
            validate_result(result, spec.name, seed)
        except ValueError as error:
            result = {
                "format_version": 1,
                "name": spec.name,
                "seed": seed,
                "status": "failed",
                "failure": f"invalid native harness self-test result: {error}",
            }
    if completed.returncode != 0 and result.get("status") == "passed":
        result["status"] = "failed"
        result["failure"] = f"native harness self-test exited {completed.returncode}"
    apply_expected_failure(spec, result)
    result["host"] = {
        "execution": "native_harness",
        "duration_seconds": round(duration, 3),
        "exit_code": completed.returncode,
    }
    result["summary"] = {
        "duration_seconds": round(duration, 3),
        "phase": result.get("phase", "finished"),
        "classification": None,
        "action": result.get("last_action", "native_harness_self_test"),
        "artifact_path": str(result_path),
        "primary_failure": result.get("failure"),
        "assertion_id": result.get("assertion_id"),
        "expectation_outcome": result.get("expectation_outcome"),
        "diagnostic_outcomes": [],
    }
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"passed", "expected_failure"} else 1
