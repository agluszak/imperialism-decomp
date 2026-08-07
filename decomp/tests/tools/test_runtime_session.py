#!/usr/bin/env python3
"""Contracts for supervising one instrumented runtime-test session."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.runtime.debug.session import (
    DebuggerLifecycle,
    DebuggerTransportError,
    StopEvent,
)
from tools.runtime.models import RunConfig
from tools.runtime.session import SessionDependencies, execute_run
from tools.runtime.transports import GdbTransport


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

    def lifecycle(self) -> DebuggerLifecycle:
        return DebuggerLifecycle(
            proxy_pid=self.process.pid,
            proxy_exit_code=self.process.returncode,
            gdb_pid=5678,
            gdb_exit_code=None,
            inferior_pid=9012,
            inferior_exit_code=None,
            inferior_terminal_reason=None,
            inferior_signal=None,
            inferior_active=True,
        )

    def terminate_inferior(self) -> None:
        self.process.kill()


class InvariantGdbSession(FailingPollGdbSession):
    def __init__(self, *_args: object) -> None:
        super().__init__(*_args)
        self.stop = StopEvent(
            reason="breakpoint-hit",
            signal_name="SIGTRAP",
            breakpoint_number="1",
            raw='*stopped,reason="breakpoint-hit",bkptno="1"',
        )
        self.captured_labels = []

    def poll_stop(self) -> StopEvent | None:
        stop = self.stop
        self.stop = None
        return stop

    def consume_runtime_invariant(self) -> str:
        return "stationed_military_unit_destructor"

    def capture_stop(self, label: str, _stop: StopEvent) -> None:
        self.stop_count += 1
        self.captured_labels.append(label)


class InferiorExitGdbSession(FailingPollGdbSession):
    def __init__(self, *_args: object) -> None:
        super().__init__(*_args)
        self.terminal = False

    def poll_stop(self) -> StopEvent | None:
        if self.terminal:
            return None
        self.terminal = True
        return StopEvent("exited-normally", None, None, '*stopped,reason="exited-normally"')

    def lifecycle(self) -> DebuggerLifecycle:
        return DebuggerLifecycle(
            proxy_pid=self.process.pid,
            proxy_exit_code=None,
            gdb_pid=5678,
            gdb_exit_code=None,
            inferior_pid=9012,
            inferior_exit_code=0,
            inferior_terminal_reason="exited-normally" if self.terminal else None,
            inferior_signal=None,
            inferior_active=not self.terminal,
        )


class ProxyExitGdbSession(FailingPollGdbSession):
    def poll_stop(self) -> None:
        return None

    def lifecycle(self) -> DebuggerLifecycle:
        return DebuggerLifecycle(
            proxy_pid=self.process.pid,
            proxy_exit_code=3,
            gdb_pid=5678,
            gdb_exit_code=None,
            inferior_pid=9012,
            inferior_exit_code=None,
            inferior_terminal_reason=None,
            inferior_signal=None,
            inferior_active=True,
        )


class _NoVirtualDisplay:
    """Stands in for tools.runtime.display.virtual_display in session unit tests."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *_exception) -> bool:
        return False


class RuntimeSessionTests(unittest.TestCase):
    @staticmethod
    def _config(run_dir: Path, timeout: float = 30.0) -> RunConfig:
        return RunConfig(
            name="boot_managers",
            run_dir=run_dir,
            seed=1,
            timeout_seconds=timeout,
            use_gdb=True,
        )

    @staticmethod
    def _dependencies(root: Path, session_factory: type) -> SessionDependencies:
        def transport_factory(
            _use_gdb: bool,
            executable: Path,
            cwd: Path,
            environment: dict[str, str],
            artifact_dir: Path,
            wine_log_name: str,
        ) -> GdbTransport:
            return GdbTransport(
                executable,
                cwd,
                environment,
                artifact_dir,
                wine_log_name,
                session_factory=session_factory,
            )

        return SessionDependencies(
            executable_provider=lambda: root / "Imperialism.exe",
            prefix_provider=lambda: root / "prefix",
            environment_builder=lambda _prefix: {},
            display_factory=lambda _environment, _log: _NoVirtualDisplay(),
            sandbox_factory=lambda _run_dir, _executable, _fixture: (
                root,
                None,
                "asset-hash",
            ),
            prefix_initializer=lambda _prefix, _environment: None,
            path_translator=lambda paths, _environment: [str(path) for path in paths],
            provenance_builder=lambda *_args: {},
            transport_factory=transport_factory,
            screenshot_capture=lambda *_args, **_kwargs: None,
            sleep=lambda _seconds: None,
        )

    def test_transport_failure_cannot_be_overwritten_by_healthy_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Imperialism.exe").write_bytes(b"")
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "debug-record.json").write_text("stale", encoding="utf-8")
            result = execute_run(
                self._config(run_dir, timeout=0.0),
                self._dependencies(root, FailingPollGdbSession),
            )

        self.assertEqual(result.classification, "debugger_transport_failure")
        self.assertEqual(result.debugger_transport_error, "GDB transport disappeared")
        session = FailingPollGdbSession.instance
        self.assertIsNotNone(session)
        self.assertTrue(session.closed)
        self.assertEqual(session.process.poll_calls, 0)
        self.assertFalse((run_dir / "debug-record.json").exists())

    def test_invariant_stop_is_captured_and_fails_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Imperialism.exe").write_bytes(b"")
            run_dir = root / "run"
            result = execute_run(
                self._config(run_dir), self._dependencies(root, InvariantGdbSession)
            )

        self.assertEqual(result.classification, "runtime_invariant_violation")
        self.assertEqual(
            result.debugger_invariant, "stationed_military_unit_destructor"
        )
        session = InvariantGdbSession.instance
        self.assertIsNotNone(session)
        self.assertEqual(
            session.captured_labels,
            ["invariant-stationed-military-unit-destructor"],
        )
        self.assertEqual(session.process.returncode, -9)

    def test_clean_inferior_exit_is_authoritative_over_live_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Imperialism.exe").write_bytes(b"")
            run_dir = root / "run"
            result = execute_run(
                self._config(run_dir), self._dependencies(root, InferiorExitGdbSession)
            )
        self.assertEqual(result.classification, "exited_without_result")
        self.assertEqual(result.inferior_exit_code, 0)
        self.assertEqual(result.inferior_terminal_reason, "exited-normally")
        self.assertIsNone(result.proxy_exit_code)

    def test_proxy_exit_while_inferior_active_is_transport_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Imperialism.exe").write_bytes(b"")
            run_dir = root / "run"
            result = execute_run(
                self._config(run_dir), self._dependencies(root, ProxyExitGdbSession)
            )
        self.assertEqual(result.classification, "debugger_transport_failure")
        self.assertEqual(result.proxy_exit_code, 3)
        self.assertIsNone(result.inferior_exit_code)


if __name__ == "__main__":
    unittest.main()
