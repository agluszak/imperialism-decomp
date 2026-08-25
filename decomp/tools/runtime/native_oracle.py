"""Direct Wine launch for C++ native transition cases.

`compare_native` and `just native-oracle` use this instead of RuntimeRunner.
It keeps session.execute_run() for sandbox, Xvfb, and process control, then
reads the native result.json / captures.json. Save-backed `.imp` copies are
optional and only published when a capture still uses that transport.
"""

from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import sys
from typing import Any

from tools.runtime.catalog import find_test
from tools.runtime.models import HostResult, JsonObject, RunConfig
from tools.runtime.protocol import load_captures, read_json_file
from tools.runtime.session import execute_run


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
NATIVE_ORACLE = "native_transition_oracle"
NATIVE_CASE_ENV = "IMPERIALISM_NATIVE_CASE"
REQUIRED_CAPTURES = ("before", "case", "after", "result")

ExecuteFn = Callable[[RunConfig], HostResult]


def fixture_directory() -> Path:
    override = os.environ.get("IMPERIALISM_SAVE_FIXTURES")
    return Path(override) if override else REPO_ROOT.parent / "fixtures" / "retail"


def runtime_result_dir() -> Path:
    override = os.environ.get("IMPERIALISM_RUNTIME_RESULT_DIR")
    return Path(override) if override else BUILD_DIR / "runtime-results"


def copy_save_backed_captures(run_dir: Path, captures: JsonObject) -> None:
    """Copy save-backed before/after .imp files next to result.json when present."""
    game_dir = run_dir / "game"
    for capture_name, payload in captures.items():
        if not isinstance(payload, dict):
            continue
        save_name = payload.get("save")
        if not isinstance(save_name, str) or not save_name.endswith(".imp"):
            continue
        candidates = (
            game_dir / "Save" / f"rt_native_{capture_name}.imp",
            game_dir / "save" / f"rt_native_{capture_name}.imp",
        )
        source = next((path for path in candidates if path.is_file()), None)
        if source is None:
            continue
        (run_dir / save_name).write_bytes(source.read_bytes())


def _fail(message: str, *, result: JsonObject | None = None) -> int:
    print(message, file=sys.stderr)
    if result is not None:
        failure = result.get("failure")
        if failure:
            print(str(failure), file=sys.stderr)
    return 1


def _process_failed(host: HostResult) -> str | None:
    if host.classification is not None:
        return host.classification
    if host.inferior_exit_code not in {None, 0}:
        return f"process exited {host.inferior_exit_code}"
    return None


def run_native_transition(
    case: str,
    *,
    seed: int = 1,
    timeout_seconds: float | None = None,
    result_dir: Path | None = None,
    execute: ExecuteFn = execute_run,
    fixture_dir: Path | None = None,
) -> int:
    spec = find_test(NATIVE_ORACLE)
    if spec is None or spec.fixture is None:
        return _fail(f"catalog is missing {NATIVE_ORACLE}")
    if seed < 1:
        return _fail("--seed must be a positive integer")

    run_dir = result_dir if result_dir is not None else runtime_result_dir()
    run_dir.mkdir(parents=True, exist_ok=True)
    fixture = (fixture_dir or fixture_directory()) / spec.fixture.filename
    if not fixture.is_file():
        return _fail(f"missing save fixture {fixture}")

    os.environ[NATIVE_CASE_ENV] = case
    timeout = spec.default_timeout if timeout_seconds is None else timeout_seconds
    host = execute(
        RunConfig(
            name=NATIVE_ORACLE,
            run_dir=run_dir,
            seed=seed,
            timeout_seconds=timeout,
            use_gdb=False,
            fixture=fixture,
        )
    )

    process_error = _process_failed(host)
    result_path = run_dir / "result.json"
    result = read_json_file(result_path)
    if process_error is not None:
        return _fail(f"native transition {case}: {process_error}", result=result)
    if result is None:
        return _fail(f"native transition {case}: missing result.json")
    if result.get("status") != "passed":
        return _fail(
            f"native transition {case}: {result.get('status')}",
            result=result,
        )

    try:
        captures: dict[str, Any] = load_captures(result, result_path)
    except ValueError as error:
        return _fail(f"native transition {case}: {error}")
    missing = [name for name in REQUIRED_CAPTURES if name not in captures]
    if missing:
        return _fail(
            f"native transition {case}: missing capture(s) {', '.join(missing)}"
        )
    try:
        copy_save_backed_captures(run_dir, captures)
    except FileNotFoundError as error:
        return _fail(f"native transition {case}: {error}")

    print(f"native-oracle {case}: passed", file=sys.stderr)
    return 0
