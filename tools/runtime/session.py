"""Prepare, launch, poll, and tear down one isolated runtime attempt."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Callable

from tools.runtime.artifacts import capture_failure_screenshot
from tools.runtime.classification import classify_poll, no_progress_budget_seconds
from tools.runtime.display import virtual_display
from tools.runtime.models import HostResult, JsonObject, RunConfig
from tools.runtime.protocol import read_json_file
from tools.runtime.transports import (
    RuntimeTransport,
    TransportSnapshot,
    create_transport,
)
from tools.runtime.wine import (
    initialize_wine_prefix,
    prepare_game_sandbox,
    prefix_environment,
    runtime_provenance,
    windows_paths,
    worktree_prefix,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
POLL_INTERVAL_SECONDS = 0.05


TransportFactory = Callable[
    [bool, Path, Path, dict[str, str], Path, str], RuntimeTransport
]


@dataclass(frozen=True)
class PreparedAttempt:
    game_dir: Path
    sandbox_executable: Path
    staged_fixture: Path | None
    asset_manifest_sha256: str


@dataclass(frozen=True)
class SessionDependencies:
    executable_provider: Callable[[], Path] = lambda: BUILD_DIR / "Imperialism.exe"
    prefix_provider: Callable[[], Path] = worktree_prefix
    environment_builder: Callable[[Path], dict[str, str]] = prefix_environment
    display_factory: Callable = virtual_display
    sandbox_factory: Callable = prepare_game_sandbox
    prefix_initializer: Callable = initialize_wine_prefix
    path_translator: Callable = windows_paths
    provenance_builder: Callable = runtime_provenance
    transport_factory: TransportFactory = create_transport
    screenshot_capture: Callable = capture_failure_screenshot
    monotonic: Callable[[], float] = time.monotonic
    wall_time: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep


def _prepare_environment(
    config: RunConfig,
    environment: dict[str, str],
    result_path: Path,
    heartbeat_path: Path,
    debug_record_path: Path,
    staged_fixture: Path | None,
    translate: Callable,
) -> None:
    translated_paths = [result_path, heartbeat_path, debug_record_path]
    if staged_fixture is not None:
        translated_paths.append(staged_fixture)
    translated = translate(translated_paths, environment)
    environment.update(
        {
            "IMPERIALISM_RUNTIME_TEST": config.name,
            "IMPERIALISM_RUNTIME_TEST_RESULT": translated[0],
            "IMPERIALISM_RUNTIME_TEST_HEARTBEAT": translated[1],
            "IMPERIALISM_RUNTIME_TEST_DEBUG_RECORD": translated[2],
            "IMPERIALISM_RUNTIME_TEST_SEED": str(config.seed),
            "IMPERIALISM_RUNTIME_TEST_PHASE_TIMEOUT_MS": str(
                config.phase_timeout_ms
            ),
        }
    )
    if staged_fixture is not None:
        environment["IMPERIALISM_RUNTIME_TEST_FIXTURE"] = translated[3]
    if config.use_gdb:
        environment["IMPERIALISM_RUNTIME_TEST_DEBUGGER"] = "1"


def _prepare_attempt(
    config: RunConfig,
    dependencies: SessionDependencies,
    prefix: Path,
    environment: dict[str, str],
    executable: Path,
    result_path: Path,
    heartbeat_path: Path,
    debug_record_path: Path,
    mark: Callable[[str], None],
) -> PreparedAttempt:
    game_dir, staged_fixture, asset_manifest_sha256 = dependencies.sandbox_factory(
        config.run_dir, executable, config.fixture
    )
    sandbox_executable = game_dir / executable.name
    mark("sandbox")
    dependencies.prefix_initializer(prefix, environment)
    mark("prefix")
    _prepare_environment(
        config,
        environment,
        result_path,
        heartbeat_path,
        debug_record_path,
        staged_fixture,
        dependencies.path_translator,
    )
    mark("path_translation")
    return PreparedAttempt(
        game_dir=game_dir,
        sandbox_executable=sandbox_executable,
        staged_fixture=staged_fixture,
        asset_manifest_sha256=asset_manifest_sha256,
    )


def _heartbeat_age(path: Path, heartbeat: JsonObject | None, wall_time: Callable) -> float | None:
    if heartbeat is None:
        return None
    try:
        return wall_time() - path.stat().st_mtime
    except OSError:
        return None


def _poll_attempt(
    config: RunConfig,
    dependencies: SessionDependencies,
    transport: RuntimeTransport,
    snapshot: TransportSnapshot,
    result_path: Path,
    heartbeat_path: Path,
    pid_path: Path,
    prefix: Path,
    started: float,
) -> TransportSnapshot:
    budget_seconds = no_progress_budget_seconds(config.phase_timeout_ms)
    while not snapshot.terminal:
        snapshot = transport.poll(result_path.is_file())
        if snapshot.inferior_pid is not None and not pid_path.is_file():
            pid_path.write_text(f"{snapshot.inferior_pid}\n", encoding="utf-8")
        if snapshot.terminal:
            if snapshot.classification == "runtime_invariant_violation":
                dependencies.screenshot_capture(
                    config.run_dir / "failure-screenshot.png", wineprefix=prefix
                )
                snapshot = transport.stop(snapshot.classification)
            break

        heartbeat = read_json_file(heartbeat_path)
        classification = classify_poll(
            heartbeat,
            _heartbeat_age(heartbeat_path, heartbeat, dependencies.wall_time),
            budget_seconds,
            process_age_seconds=dependencies.monotonic() - started,
        )
        if (
            classification is None
            and dependencies.monotonic() - started > config.timeout_seconds
        ):
            classification = "action_timeout"
        if classification is not None:
            dependencies.screenshot_capture(
                config.run_dir / "failure-screenshot.png",
                owner_pid=snapshot.inferior_pid,
                wineprefix=prefix,
            )
            snapshot = transport.stop(classification)
            break
        dependencies.sleep(POLL_INTERVAL_SECONDS)
    return snapshot


def _close_attempt(
    transport: RuntimeTransport | None,
    pid_path: Path,
    display_context,
) -> TransportSnapshot | None:
    try:
        if transport is not None:
            transport.close()
            return transport.snapshot
        return None
    finally:
        pid_path.unlink(missing_ok=True)
        display_context.__exit__(None, None, None)


def _build_host_result(
    config: RunConfig,
    dependencies: SessionDependencies,
    prepared: PreparedAttempt,
    transport: RuntimeTransport | None,
    snapshot: TransportSnapshot,
    heartbeat_path: Path,
    display_name: str | None,
    started: float,
    phase_started: float,
    phase_timings: dict[str, float],
) -> HostResult:
    heartbeat = read_json_file(heartbeat_path) or {}
    provenance = dependencies.provenance_builder(
        prepared.sandbox_executable,
        prepared.asset_manifest_sha256,
        display_name,
        prepared.staged_fixture,
    )
    phase = heartbeat.get("phase")
    action = heartbeat.get("last_action")
    return HostResult(
        classification=snapshot.classification,
        display=display_name or "host",
        artifact_dir=config.run_dir,
        duration_seconds=round(dependencies.monotonic() - started, 3),
        phase_seconds={
            **phase_timings,
            "teardown": round(dependencies.monotonic() - phase_started, 3),
        },
        phase=phase if isinstance(phase, str) else None,
        action=action if isinstance(action, str) else None,
        wine_exit=snapshot.inferior_exit_code,
        proxy_pid=snapshot.proxy_pid,
        proxy_exit_code=snapshot.proxy_exit_code,
        gdb_pid=snapshot.gdb_pid,
        gdb_exit_code=snapshot.gdb_exit_code,
        inferior_pid=snapshot.inferior_pid,
        inferior_exit_code=snapshot.inferior_exit_code,
        inferior_terminal_reason=snapshot.inferior_terminal_reason,
        inferior_signal=snapshot.inferior_signal,
        debugger=(
            transport.debugger_name
            if transport is not None
            else "gdb" if config.use_gdb else "none"
        ),
        debugger_stop_count=transport.stop_count if transport is not None else 0,
        debugger_transport_error=snapshot.debugger_error,
        debugger_invariant=snapshot.debugger_invariant,
        debugger_signal=snapshot.debugger_signal,
        game_dir=prepared.game_dir,
        provenance=provenance,
        fixture_metadata=config.fixture_metadata,
        seed=config.seed,
        timeout_seconds=config.timeout_seconds,
        phase_timeout_ms=config.phase_timeout_ms,
    )


def execute_run(
    config: RunConfig, dependencies: SessionDependencies | None = None
) -> HostResult:
    """Execute one prepared attempt through the selected narrow transport."""
    deps = dependencies or SessionDependencies()
    executable = deps.executable_provider()
    if not executable.is_file():
        raise SystemExit(f"Missing {executable}; run `just runtime-test-build` first")

    config.run_dir.mkdir(parents=True, exist_ok=True)
    result_path = config.run_dir / "result.json"
    heartbeat_path = config.run_dir / "heartbeat.json"
    debug_record_path = config.run_dir / "debug-record.json"
    pid_path = config.run_dir / "pid"
    for path in (result_path, heartbeat_path, debug_record_path, pid_path):
        path.unlink(missing_ok=True)

    prefix = deps.prefix_provider()
    environment = deps.environment_builder(prefix)
    if config.winedebug is not None:
        environment["WINEDEBUG"] = config.winedebug

    started = deps.monotonic()
    phase_started = started
    phase_timings: dict[str, float] = {}

    def mark(phase: str) -> None:
        nonlocal phase_started
        now = deps.monotonic()
        phase_timings[phase] = round(now - phase_started, 3)
        phase_started = now

    display_context = deps.display_factory(environment, config.run_dir / "xvfb.log")
    display_name = display_context.__enter__()
    mark("display")
    transport: RuntimeTransport | None = None
    snapshot = TransportSnapshot()
    prepared: PreparedAttempt
    try:
        prepared = _prepare_attempt(
            config,
            deps,
            prefix,
            environment,
            executable,
            result_path,
            heartbeat_path,
            debug_record_path,
            mark,
        )
        transport = deps.transport_factory(
            config.use_gdb,
            prepared.sandbox_executable,
            prepared.game_dir,
            environment,
            config.run_dir,
            config.wine_log_name,
        )
        snapshot = transport.start()
        mark("launch")
        if snapshot.inferior_pid is not None:
            pid_path.write_text(f"{snapshot.inferior_pid}\n", encoding="utf-8")
        snapshot = _poll_attempt(
            config,
            deps,
            transport,
            snapshot,
            result_path,
            heartbeat_path,
            pid_path,
            prefix,
            started,
        )
        mark("run")
    finally:
        final_snapshot = _close_attempt(transport, pid_path, display_context)
        if final_snapshot is not None:
            snapshot = final_snapshot

    return _build_host_result(
        config,
        deps,
        prepared,
        transport,
        snapshot,
        heartbeat_path,
        display_name,
        started,
        phase_started,
        phase_timings,
    )
