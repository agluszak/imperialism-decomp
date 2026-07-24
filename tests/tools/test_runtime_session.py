#!/usr/bin/env python3
"""Contracts for supervising one instrumented runtime-test session."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.debug.session import DebuggerTransportError
from tools.runtime.session import execute_run


class FakeProcess:
    pid = 1234

    def __init__(self) -> None:
        self.returncode = None
        self.poll_calls = 0

    def poll(self) -> int | None:
        self.poll_calls += 1
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float) -> int:
        del timeout
        return self.returncode


class FailingPollGdbSession:
    instance: "FailingPollGdbSession | None" = None

    def __init__(self, *_args: object) -> None:
        self.process = FakeProcess()
        self.run_dir = Path(_args[3])
        self.stop_count = 0
        self.closed = False
        type(self).instance = self

    def start(self) -> FakeProcess:
        (self.run_dir / "heartbeat.json").write_text(
            '{"elapsed_ms": 1000, "last_progress_ms": 1000}\n',
            encoding="utf-8",
        )
        return self.process

    def poll_stop(self) -> None:
        raise DebuggerTransportError("GDB transport disappeared")

    def close(self) -> None:
        self.closed = True

    def interrupt_and_capture(self, _classification: str) -> None:
        raise DebuggerTransportError("GDB transport disappeared")


class RuntimeSessionTests(unittest.TestCase):
    def test_transport_failure_cannot_be_overwritten_by_healthy_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Imperialism.exe").write_bytes(b"")
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "debug-record.json").write_text("stale", encoding="utf-8")

            with (
                patch("tools.runtime.session.BUILD_DIR", root),
                patch("tools.runtime.session.GdbSession", FailingPollGdbSession),
                patch("tools.runtime.session.initialize_wine_prefix"),
                patch("tools.runtime.session.prefix_environment", return_value={}),
                patch(
                    "tools.runtime.session.windows_path",
                    side_effect=lambda path, _environment: str(path),
                ),
                patch("tools.runtime.session.retail_game_dir", return_value=root),
                patch("tools.runtime.session.shut_down_wine_prefix"),
                patch("tools.runtime.session.capture_failure_screenshot"),
                patch(
                    "tools.runtime.session.time.monotonic",
                    side_effect=(0.0, 0.1, 0.2, 0.3),
                ),
            ):
                result = execute_run(
                    name="boot_managers",
                    run_dir=run_dir,
                    seed=1,
                    timeout=0.0,
                    phase_timeout_ms=15_000,
                    winedebug=None,
                    wine_log_name="wine.log",
                )

        self.assertEqual(result["classification"], "debugger_transport_failure")
        self.assertEqual(result["debugger_transport_error"], "GDB transport disappeared")
        session = FailingPollGdbSession.instance
        self.assertIsNotNone(session)
        self.assertTrue(session.closed)
        self.assertEqual(session.process.poll_calls, 0)
        self.assertFalse((run_dir / "debug-record.json").exists())


if __name__ == "__main__":
    unittest.main()
