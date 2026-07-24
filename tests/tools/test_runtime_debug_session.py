#!/usr/bin/env python3
"""Contracts for the shared runtime GDB/MI transport."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import tempfile
from pathlib import Path

from tools.runtime.debug.mi_protocol import parse_mi_record, stream_text
from tools.runtime.debug.session import is_terminal_stop, stop_event_from_record
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
