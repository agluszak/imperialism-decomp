#!/usr/bin/env python3
"""Shared transport-contract tests for direct Wine and GDB supervision."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.runtime.debug.session import DebuggerLifecycle
from tools.runtime.transports import DirectWineTransport, GdbTransport


class _ExitedProcess:
    pid = 41
    returncode = 0

    def poll(self) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, _timeout: float) -> int:
        return self.returncode


class _CleanGdbSession:
    stop_count = 0

    def __init__(self, *_args: object) -> None:
        self.closed = False

    def start(self) -> None:
        return None

    def poll_stop(self) -> None:
        return None

    def lifecycle(self) -> DebuggerLifecycle:
        return DebuggerLifecycle(
            proxy_pid=42,
            proxy_exit_code=None,
            gdb_pid=43,
            gdb_exit_code=None,
            inferior_pid=44,
            inferior_exit_code=0,
            inferior_terminal_reason="exited-normally",
            inferior_signal=None,
            inferior_active=False,
        )

    def close(self) -> None:
        self.closed = True


class RuntimeTransportTests(unittest.TestCase):
    def test_direct_and_gdb_transports_share_terminal_snapshot_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "Imperialism.exe"
            executable.write_bytes(b"")
            direct = DirectWineTransport(
                executable,
                root,
                {},
                root,
                "wine.log",
                process_factory=lambda *_args, **_kwargs: _ExitedProcess(),
            )
            gdb = GdbTransport(
                executable,
                root,
                {},
                root,
                "wine.log",
                session_factory=_CleanGdbSession,
            )

            for transport in (direct, gdb):
                transport.start()
                terminal = transport.poll(result_exists=True)
                self.assertTrue(terminal.terminal)
                self.assertIsNone(terminal.classification)
                self.assertEqual(terminal.inferior_exit_code, 0)
                transport.close()


if __name__ == "__main__":
    unittest.main()
