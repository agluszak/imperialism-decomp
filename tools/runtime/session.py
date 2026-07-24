"""Launch and supervise one isolated instrumented Wine session."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import time

from tools.runtime.artifacts import capture_failure_screenshot
from tools.runtime.classification import classify_exit, classify_poll, no_progress_budget_seconds
from tools.runtime.protocol import read_json_file
from tools.runtime.wine import (
    initialize_wine_prefix,
    prefix_environment,
    retail_game_dir,
    shut_down_wine_prefix,
    windows_path,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
POLL_INTERVAL_SECONDS = 0.5

def execute_run(
    name: str,
    run_dir: Path,
    seed: int,
    timeout: float,
    phase_timeout_ms: int,
    winedebug: str | None,
    wine_log_name: str,
    fixture: Path | None = None,
) -> dict:
    """One isolated game run; returns host metadata including classification."""
    executable = BUILD_DIR / "Imperialism.exe"
    if not executable.is_file():
        raise SystemExit(f"Missing {executable}; run `just runtime-test-build` first")

    prefix = run_dir / "prefix"
    result_path = run_dir / "result.json"
    heartbeat_path = run_dir / "heartbeat.json"
    result_path.unlink(missing_ok=True)
    heartbeat_path.unlink(missing_ok=True)

    environment = prefix_environment(prefix)
    if winedebug is not None:
        environment["WINEDEBUG"] = winedebug

    classification: str | None = None
    budget_seconds = no_progress_budget_seconds(phase_timeout_ms)
    pid_path = run_dir / "pid"
    started = time.monotonic()
    try:
        initialize_wine_prefix(prefix, environment)

        environment["IMPERIALISM_RUNTIME_TEST"] = name
        environment["IMPERIALISM_RUNTIME_TEST_RESULT"] = windows_path(
            result_path, environment
        )
        environment["IMPERIALISM_RUNTIME_TEST_HEARTBEAT"] = windows_path(
            heartbeat_path, environment
        )
        environment["IMPERIALISM_RUNTIME_TEST_SEED"] = str(seed)
        environment["IMPERIALISM_RUNTIME_TEST_PHASE_TIMEOUT_MS"] = str(phase_timeout_ms)
        if fixture is not None:
            environment["IMPERIALISM_RUNTIME_TEST_FIXTURE"] = windows_path(
                fixture, environment
            )

        with (run_dir / wine_log_name).open("wb") as wine_log:
            process = subprocess.Popen(
                ["wine", str(executable)],
                cwd=retail_game_dir(),
                env=environment,
                stdout=wine_log,
                stderr=subprocess.STDOUT,
            )
            pid_path.write_text(f"{process.pid}\n", encoding="utf-8")
            while True:
                returncode = process.poll()
                if returncode is not None:
                    classification = classify_exit(returncode, result_path.is_file())
                    break
                heartbeat = read_json_file(heartbeat_path)
                heartbeat_age = None
                if heartbeat is not None:
                    try:
                        heartbeat_age = time.time() - heartbeat_path.stat().st_mtime
                    except OSError:
                        heartbeat = None
                classification = classify_poll(
                    heartbeat,
                    heartbeat_age,
                    budget_seconds,
                    process_age_seconds=time.monotonic() - started,
                )
                if classification is None and time.monotonic() - started > timeout:
                    classification = "action_timeout"
                if classification is not None:
                    capture_failure_screenshot(run_dir / "failure-screenshot.png")
                    process.kill()
                    process.wait(timeout=30)
                    returncode = process.returncode
                    break
                time.sleep(POLL_INTERVAL_SECONDS)
    finally:
        shut_down_wine_prefix(environment)
        pid_path.unlink(missing_ok=True)
        shutil.rmtree(prefix, ignore_errors=True)

    return {
        "classification": classification,
        "wine_exit": returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
    }
