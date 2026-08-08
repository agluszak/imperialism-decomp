#!/usr/bin/env python3
"""Contracts for the shared runtime GDB/MI transport."""

from __future__ import annotations

import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import tempfile
from pathlib import Path

from tools.runtime.debug.mi_protocol import parse_mi_record, stream_text
from tools.runtime.debug.mi_process import DebuggerTransportError, GdbMiProcess
from tools.runtime.debug.session import (
    GdbSession,
    StopEvent,
    _parse_exit_code,
    is_terminal_stop,
    stop_event_from_record,
)
from tools.runtime.debug.symbols import LinkerMap, symbolize_gdb_report


class StopEventTests(unittest.TestCase):
    def test_signal_stop_is_structured(self) -> None:
        record = parse_mi_record(
            '*stopped,reason="signal-received",signal-name="SIGTRAP",thread-id="1"'
        )
        event = stop_event_from_record(record)
        self.assertIsNotNone(event)
        self.assertEqual(event.reason, "signal-received")
        self.assertEqual(event.signal_name, "SIGTRAP")
        self.assertIsNone(event.breakpoint_number)

    def test_non_stop_record_is_ignored(self) -> None:
        self.assertIsNone(stop_event_from_record(parse_mi_record('*running,thread-id="all"')))

    def test_normal_exit_is_terminal(self) -> None:
        event = stop_event_from_record(parse_mi_record('*stopped,reason="exited-normally"'))
        self.assertIsNotNone(event)
        self.assertTrue(is_terminal_stop(event))

    def test_console_stream_is_decoded(self) -> None:
        self.assertEqual(stream_text(parse_mi_record('~"frame zero\\n"')), "frame zero\n")

    def test_result_token_is_preserved(self) -> None:
        record = parse_mi_record('17^done')
        self.assertEqual(record.record_type, "result")
        self.assertEqual(record.message, "done")
        self.assertEqual(record.token, 17)

    def test_remote_octal_exit_code_is_parsed(self) -> None:
        self.assertEqual(_parse_exit_code("0177"), 0o177)


class GdbSessionTests(unittest.TestCase):
    def test_read_memory_decodes_mi_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "Imperialism.exe"
            executable.write_bytes(b"")
            session = GdbSession(executable, root, {}, root)
            mi = SimpleNamespace(command=lambda *_args: None)
            response = SimpleNamespace(
                result=SimpleNamespace(
                    payload={"memory": [{"begin": "0x1000", "contents": "0011aaff"}]},
                    raw='^done,memory=[{begin="0x1000",contents="0011aaff"}]',
                )
            )
            with (
                patch.object(session, "_require_mi", return_value=mi),
                patch.object(session, "_call", return_value=response),
            ):
                self.assertEqual(session.read_memory(0x1000, 4), b"\x00\x11\xaa\xff")

    def test_write_memory_uses_one_mi_byte_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "Imperialism.exe"
            executable.write_bytes(b"")
            session = GdbSession(executable, root, {}, root)
            with patch.object(session, "_command") as command:
                session.write_memory(0x2000, b"\x01\x02\xfe")
            command.assert_called_once_with(
                "-data-write-memory-bytes 0x00002000 0102fe", timeout=30.0
            )

    def test_interrupt_and_capture_uses_mi_interrupt_and_captures_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "Imperialism.exe"
            executable.write_bytes(b"")
            session = GdbSession(executable, root, {}, root)
            event = StopEvent(
                reason="signal-received",
                signal_name="SIGINT",
                breakpoint_number=None,
                raw='*stopped,reason="signal-received",signal-name="SIGINT"',
            )
            report = root / "debugger-stop-01-timeout.txt"
            with (
                patch.object(session, "poll_stop", return_value=None),
                patch.object(session, "_command") as command,
                patch.object(session, "_wait_for_stop", return_value=event),
                patch.object(session, "capture_stop", return_value=report) as capture,
            ):
                result = session.interrupt_and_capture("timeout")
            command.assert_called_once_with("-exec-interrupt --all", timeout=5)
            capture.assert_called_once_with("timeout", event)
            self.assertEqual(result, (report, event))


class LinkerMapTests(unittest.TestCase):
    def test_nearest_public_symbol_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            map_path = root / "Imperialism.map"
            map_path.write_text(
                " 0001:00015340       ?Render@TView@@UAEXXZ 00416340 f TView.cpp.obj\n",
                encoding="ascii",
            )
            symbol = LinkerMap.read(map_path).lookup(0x00416355)
            self.assertIsNotNone(symbol)
            self.assertEqual(symbol.address, 0x00416340)

    def test_decorated_symbol_is_selected_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            map_path = Path(temporary) / "Imperialism.map"
            map_path.write_text(
                " 0003:00005938       _g_runtimeDebugRecord 005cb938   RuntimeDebuggerTrap.cpp.obj\n",
                encoding="ascii",
            )
            symbol = LinkerMap.read(map_path).find_decorated("_g_runtimeDebugRecord")
            self.assertIsNotNone(symbol)
            self.assertEqual(symbol.address, 0x005CB938)

    def test_data_symbol_is_not_used_as_a_stack_function(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            map_path = Path(temporary) / "Imperialism.map"
            map_path.write_text(
                " 0003:00005938       _g_runtimeDebugRecord 005cb938   RuntimeDebuggerTrap.cpp.obj\n",
                encoding="ascii",
            )
            resolution = LinkerMap.read(map_path).resolve(0x005CB940)
            self.assertIsNone(resolution.symbol)
            self.assertEqual(resolution.reason, "nearest public is data")

    def test_unbounded_gap_is_reported_as_low_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            map_path = Path(temporary) / "Imperialism.map"
            map_path.write_text(
                " 0001:00015340       ?Render@TView@@UAEXXZ 00416340 f TView.cpp.obj\n",
                encoding="ascii",
            )
            resolution = LinkerMap.read(map_path).resolve(0x00418340)
            self.assertIsNone(resolution.symbol)
            self.assertEqual(resolution.confidence, "low")

    def test_report_produces_symbolized_stack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            map_path = root / "Imperialism.map"
            report_path = root / "debugger-stop-01-sigsegv.txt"
            map_path.write_text(
                " 0001:00015340       ?Render@TView@@UAEXXZ 00416340 f TView.cpp.obj\n",
                encoding="ascii",
            )
            report_path.write_text("#0  0x00416355 in ?? ()\n", encoding="utf-8")
            output = symbolize_gdb_report(report_path, map_path)
            self.assertIsNotNone(output)
            self.assertIn("TView::Render", output.read_text(encoding="utf-8"))


class GdbMiProcessTests(unittest.IsolatedAsyncioTestCase):
    def fake_command(self) -> tuple[str, ...]:
        script = Path(__file__).parent / "fixtures" / "fake_gdb_mi.py"
        return (sys.executable, str(script))

    async def test_correlates_result_while_queueing_async_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transport = GdbMiProcess(
                root, root / "gdb.log", command=self.fake_command()
            )
            await transport.start(root / "inferior.exe")
            try:
                result = await transport.command("-emit-interleaved")
                events = await transport.drain_events()
            finally:
                await transport.close()
            self.assertEqual(result.result.message, "done")
            self.assertEqual(result.output, ("command output\n",))
            self.assertTrue(any(event.message == "stopped" for event in events))

    async def test_command_timeout_is_a_transport_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transport = GdbMiProcess(
                root, root / "gdb.log", command=self.fake_command()
            )
            await transport.start(root / "inferior.exe")
            try:
                with self.assertRaisesRegex(DebuggerTransportError, "timed out"):
                    await transport.command("-timeout", timeout=0.01)
            finally:
                await transport.close()

    async def test_exit_fails_pending_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transport = GdbMiProcess(
                root, root / "gdb.log", command=self.fake_command()
            )
            await transport.start(root / "inferior.exe")
            with self.assertRaisesRegex(DebuggerTransportError, "GDB exited with 7"):
                await transport.command("-exit-before-result")
            await transport.close()

    def test_report_uses_vendored_demangler_when_llvm_undname_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            map_path = root / "Imperialism.map"
            report_path = root / "debugger-stop-01-sigsegv.txt"
            map_path.write_text(
                " 0001:00015340       ?Render@TView@@UAEXXZ 00416340 f TView.cpp.obj\n",
                encoding="ascii",
            )
            report_path.write_text("#0  0x00416355 in ?? ()\n", encoding="utf-8")
            with patch("tools.runtime.debug.symbols.subprocess.run", side_effect=FileNotFoundError):
                output = symbolize_gdb_report(report_path, map_path)
            self.assertIsNotNone(output)
            self.assertIn("TView::Render", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
