#!/usr/bin/env python3
"""Shared transport-contract tests for direct Wine and GDB supervision."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.runtime.debug.session import DebuggerLifecycle
from tools.runtime.transports import (
    WATCH_ENV,
    DirectWineTransport,
    GdbTransport,
    watch_addresses,
)


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
        self.auto_continue: bool | None = None
        self.breakpoints: list[tuple[int, str | None]] = []
        self.continued = 0

    def start(self, auto_continue: bool = True) -> None:
        self.auto_continue = auto_continue
        return None

    def set_breakpoint(self, address: int, condition: str | None = None) -> str:
        self.breakpoints.append((address, condition))
        return str(len(self.breakpoints))

    def continue_inferior(self) -> None:
        self.continued += 1

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


class WatchAddressParsingTests(unittest.TestCase):
    """IMPERIALISM_RUNTIME_GDB_WATCH drives an investigation without a bespoke session."""

    def test_bare_addresses(self) -> None:
        self.assertEqual(watch_addresses("0x4013d7"), [(0x4013D7, None)])
        self.assertEqual(
            watch_addresses("0x4013d7;0x4013d9"), [(0x4013D7, None), (0x4013D9, None)]
        )

    def test_condition_after_the_colon_may_contain_spaces(self) -> None:
        self.assertEqual(
            watch_addresses("0x4013d9:$eax == 0"), [(0x4013D9, "$eax == 0")]
        )
        self.assertEqual(
            watch_addresses("0x4013d9:$eax == 0;0x4013d7"),
            [(0x4013D9, "$eax == 0"), (0x4013D7, None)],
        )

    def test_unparsable_entries_are_skipped_not_fatal(self) -> None:
        self.assertEqual(watch_addresses("junk;0x10;"), [(0x10, None)])
        self.assertEqual(watch_addresses(""), [])

    def test_environment_is_the_default_source(self) -> None:
        with mock.patch.dict(os.environ, {WATCH_ENV: "0x1234"}, clear=False):
            self.assertEqual(watch_addresses(), [(0x1234, None)])
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(watch_addresses(), [])


class WatchBreakpointStartTests(unittest.TestCase):
    def _transport(self, root: Path) -> GdbTransport:
        executable = root / "Imperialism.exe"
        executable.write_bytes(b"")
        return GdbTransport(
            executable, root, {}, root, "wine.log", session_factory=_CleanGdbSession
        )

    def test_unwatched_start_keeps_the_auto_continue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            transport = self._transport(Path(temporary))
            with mock.patch.dict(os.environ, {}, clear=True):
                transport.start()
            self.assertIs(transport.session.auto_continue, True)
            self.assertEqual(transport.session.breakpoints, [])
            self.assertEqual(transport.session.continued, 0)

    def test_watched_start_inserts_before_continuing(self) -> None:
        """-break-insert is refused once the inferior runs, so the order is the point."""
        with tempfile.TemporaryDirectory() as temporary:
            transport = self._transport(Path(temporary))
            with mock.patch.dict(
                os.environ, {WATCH_ENV: "0x4013d9:$eax == 0;0x4013d7"}, clear=True
            ):
                transport.start()
            self.assertIs(transport.session.auto_continue, False)
            self.assertEqual(
                transport.session.breakpoints,
                [(0x4013D9, "$eax == 0"), (0x4013D7, None)],
            )
            self.assertEqual(transport.session.continued, 1)


if __name__ == "__main__":
    unittest.main()
