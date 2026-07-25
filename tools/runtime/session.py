"""Launch and supervise one isolated instrumented Wine session."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import time

from tools.runtime.artifacts import capture_failure_screenshot
from tools.runtime.classification import (
    classify_exit,
    classify_inferior_exit,
    classify_poll,
    no_progress_budget_seconds,
)
from tools.runtime.debug.session import DebuggerTransportError, GdbSession, is_terminal_stop
from tools.runtime.display import virtual_display
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
    use_gdb: bool = True,
) -> dict:
    """One isolated game run; returns host metadata including classification."""
    executable = BUILD_DIR / "Imperialism.exe"
    if not executable.is_file():
        raise SystemExit(f"Missing {executable}; run `just runtime-test-build` first")

    prefix = run_dir / "prefix"
    result_path = run_dir / "result.json"
    heartbeat_path = run_dir / "heartbeat.json"
    debug_record_path = run_dir / "debug-record.json"
    result_path.unlink(missing_ok=True)
    heartbeat_path.unlink(missing_ok=True)
    debug_record_path.unlink(missing_ok=True)

    environment = prefix_environment(prefix)
    if winedebug is not None:
        environment["WINEDEBUG"] = winedebug

    classification: str | None = None
    debugger_error: str | None = None
    debugger_invariant: str | None = None
    debugger_signal: str | None = None
    captured_stops: set[str] = set()
    debugger: GdbSession | None = None
    direct_process: subprocess.Popen[bytes] | None = None
    proxy_pid: int | None = None
    proxy_exit_code: int | None = None
    gdb_pid: int | None = None
    gdb_exit_code: int | None = None
    inferior_pid: int | None = None
    inferior_exit_code: int | None = None
    inferior_terminal_reason: str | None = None
    inferior_signal: str | None = None
    budget_seconds = no_progress_budget_seconds(phase_timeout_ms)
    pid_path = run_dir / "pid"
    started = time.monotonic()
    display_stack = virtual_display(environment, run_dir / "xvfb.log")
    virtual_display_name = display_stack.__enter__()
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
        environment["IMPERIALISM_RUNTIME_TEST_DEBUG_RECORD"] = windows_path(
            debug_record_path, environment
        )
        if fixture is not None:
            environment["IMPERIALISM_RUNTIME_TEST_FIXTURE"] = windows_path(
                fixture, environment
            )

        if use_gdb:
            environment["IMPERIALISM_RUNTIME_TEST_DEBUGGER"] = "1"
            debugger = GdbSession(
                executable, retail_game_dir(), environment, run_dir
            )
            try:
                debugger.start()
                lifecycle = debugger.lifecycle()
                proxy_pid = lifecycle.proxy_pid
                gdb_pid = lifecycle.gdb_pid
                inferior_pid = lifecycle.inferior_pid
            except DebuggerTransportError as error:
                debugger_error = str(error)
                classification = "debugger_transport_failure"
        else:
            wine_log = (run_dir / wine_log_name).open("wb")
            direct_process = subprocess.Popen(
                ["wine", str(executable)], cwd=retail_game_dir(), env=environment,
                stdout=wine_log, stderr=subprocess.STDOUT,
            )
            inferior_pid = direct_process.pid
        if inferior_pid is not None:
            pid_path.write_text(f"{inferior_pid}\n", encoding="utf-8")
        if classification is None and (debugger is not None or direct_process is not None):
            while True:
                if debugger is not None:
                    try:
                        stop = debugger.poll_stop()
                        while stop is not None:
                            if is_terminal_stop(stop):
                                break
                            debugger_invariant = debugger.consume_runtime_invariant()
                            if debugger_invariant is not None:
                                label = "invariant-" + debugger_invariant.replace("_", "-")
                                debugger.capture_stop(label, stop)
                                captured_stops.add(stop.raw)
                                classification = "runtime_invariant_violation"
                                break
                            if stop.signal_name not in {None, "SIGTRAP"}:
                                debugger_signal = stop.signal_name
                            label = (stop.signal_name or stop.reason).lower().replace("_", "-")
                            if stop.raw not in captured_stops:
                                debugger.capture_stop(label, stop)
                                captured_stops.add(stop.raw)
                            debugger.continue_inferior()
                            stop = debugger.poll_stop()
                        lifecycle = debugger.lifecycle()
                        proxy_pid = lifecycle.proxy_pid
                        proxy_exit_code = lifecycle.proxy_exit_code
                        gdb_pid = lifecycle.gdb_pid
                        gdb_exit_code = lifecycle.gdb_exit_code
                        inferior_pid = lifecycle.inferior_pid
                        inferior_exit_code = lifecycle.inferior_exit_code
                        inferior_terminal_reason = lifecycle.inferior_terminal_reason
                        inferior_signal = lifecycle.inferior_signal
                    except DebuggerTransportError as error:
                        debugger_error = str(error)
                        classification = "debugger_transport_failure"
                        break
                    if inferior_pid is not None and not pid_path.is_file():
                        pid_path.write_text(f"{inferior_pid}\n", encoding="utf-8")
                    if inferior_terminal_reason is not None:
                        classification = classify_inferior_exit(
                            inferior_terminal_reason,
                            inferior_exit_code,
                            inferior_signal,
                            result_path.is_file(),
                        )
                        break
                    if proxy_exit_code is not None or gdb_exit_code is not None:
                        classification = "debugger_transport_failure"
                        debugger_error = (
                            f"debugger transport exited while inferior was active: "
                            f"proxy={proxy_exit_code}, gdb={gdb_exit_code}"
                        )
                        break
                if classification == "runtime_invariant_violation":
                    capture_failure_screenshot(
                        run_dir / "failure-screenshot.png", wineprefix=prefix
                    )
                    if debugger is not None:
                        debugger.terminate_inferior()
                    break
                direct_returncode = (
                    direct_process.poll() if direct_process is not None else None
                )
                if direct_process is not None and direct_returncode is not None:
                    inferior_exit_code = direct_returncode
                    inferior_terminal_reason = "process-exited"
                    if debugger_signal is not None and not result_path.is_file():
                        classification = "crash"
                    else:
                        classification = classify_exit(
                            direct_returncode, result_path.is_file()
                        )
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
                    capture_failure_screenshot(
                        run_dir / "failure-screenshot.png",
                        owner_pid=direct_process.pid if direct_process is not None else None,
                        wineprefix=prefix,
                    )
                    if debugger is not None:
                        try:
                            _, stop = debugger.interrupt_and_capture(classification)
                            if stop is not None and stop.signal_name not in {None, "SIGINT", "SIGTRAP"}:
                                debugger_signal = stop.signal_name
                                classification = "crash"
                        except DebuggerTransportError as error:
                            debugger_error = str(error)
                        debugger.terminate_inferior()
                    elif direct_process is not None:
                        direct_process.kill()
                        direct_process.wait(timeout=30)
                        inferior_exit_code = direct_process.returncode
                        inferior_terminal_reason = "host-terminated"
                    break
                time.sleep(POLL_INTERVAL_SECONDS)
    finally:
        if debugger is not None:
            try:
                lifecycle = debugger.lifecycle()
                proxy_pid = lifecycle.proxy_pid
                proxy_exit_code = lifecycle.proxy_exit_code
                gdb_pid = lifecycle.gdb_pid
                gdb_exit_code = lifecycle.gdb_exit_code
                inferior_pid = lifecycle.inferior_pid
                inferior_exit_code = lifecycle.inferior_exit_code
                inferior_terminal_reason = lifecycle.inferior_terminal_reason
                inferior_signal = lifecycle.inferior_signal
            except DebuggerTransportError:
                pass
            debugger.close()
        if not use_gdb and 'wine_log' in locals():
            wine_log.close()
        shut_down_wine_prefix(environment)
        pid_path.unlink(missing_ok=True)
        shutil.rmtree(prefix, ignore_errors=True)
        # After the prefix is gone: wineserver has to reach the same X display the
        # session used, so the virtual server outlives it.
        display_stack.__exit__(None, None, None)

    return {
        "classification": classification,
        "display": virtual_display_name or "host",
        "wine_exit": inferior_exit_code,
        "proxy_pid": proxy_pid,
        "proxy_exit_code": proxy_exit_code,
        "gdb_pid": gdb_pid,
        "gdb_exit_code": gdb_exit_code,
        "inferior_pid": inferior_pid,
        "inferior_exit_code": inferior_exit_code,
        "inferior_terminal_reason": inferior_terminal_reason,
        "inferior_signal": inferior_signal,
        "duration_seconds": round(time.monotonic() - started, 3),
        "debugger": "gdb" if use_gdb else "none",
        "debugger_stop_count": debugger.stop_count if debugger is not None else 0,
        "debugger_transport_error": debugger_error,
        "debugger_invariant": debugger_invariant,
        "debugger_signal": debugger_signal,
    }
