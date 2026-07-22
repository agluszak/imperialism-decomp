#!/usr/bin/env python3
"""Tests for the research-tooling additions: dotenv loading, jump-table operand
parsing, the query daemon's wire protocol, and screenshot window discovery."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tools.common import ghidra_env
from tools.ghidra import daemon
from tools.ghidra.jumptable import looks_like_code_address, parse_jmp_table_operand
from tools.ghidra.query_registry import COMMANDS
from tools.ghidra.xrefs_to import parse_query
from tools.runtime.screenshot import WININFO_LINE_RE


class DotenvTests(unittest.TestCase):
    def test_loads_values_without_overriding_existing_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "# comment",
                        'QUOTED_VALUE="/path/with spaces/Imperialism.exe"',
                        "PLAIN_VALUE=hello",
                        "PRESET_VALUE=from_file",
                        "",
                        "not a key value line",
                    ]
                ),
                encoding="utf-8",
            )
            os.environ.pop("QUOTED_VALUE", None)
            os.environ.pop("PLAIN_VALUE", None)
            os.environ["PRESET_VALUE"] = "from_env"
            try:
                ghidra_env.load_dotenv(env_path)
                self.assertEqual(os.environ["QUOTED_VALUE"], "/path/with spaces/Imperialism.exe")
                self.assertEqual(os.environ["PLAIN_VALUE"], "hello")
                self.assertEqual(os.environ["PRESET_VALUE"], "from_env")
            finally:
                os.environ.pop("QUOTED_VALUE", None)
                os.environ.pop("PLAIN_VALUE", None)
                os.environ.pop("PRESET_VALUE", None)

    def test_missing_file_is_a_no_op(self) -> None:
        ghidra_env.load_dotenv(Path("/nonexistent/definitely/.env"))


class JumpTableParseTests(unittest.TestCase):
    def test_parses_scale_first_operand_order(self) -> None:
        # capstone renders MSVC5 tables as `jmp dword ptr [edx*4 + 0x5db6fc]`.
        self.assertEqual(parse_jmp_table_operand("dword ptr [edx*4 + 0x5db6fc]"), 0x5DB6FC)

    def test_parses_base_first_operand_order(self) -> None:
        self.assertEqual(parse_jmp_table_operand("dword ptr [0x459548 + eax*4]"), 0x459548)

    def test_rejects_non_table_operands(self) -> None:
        self.assertIsNone(parse_jmp_table_operand("dword ptr [eax + 0x8]"))
        self.assertIsNone(parse_jmp_table_operand("eax"))

    def test_code_address_window(self) -> None:
        self.assertTrue(looks_like_code_address(0x5DB6A0, 0x401000, 0x626C7D))
        self.assertFalse(looks_like_code_address(0x18, 0x401000, 0x626C7D))
        self.assertFalse(looks_like_code_address(0x6A21BC, 0x401000, 0x626C7D))


class DaemonProtocolTests(unittest.TestCase):
    def test_request_round_trip(self) -> None:
        line = daemon.encode_request("listing", ["0x491cc0", "--flag"])
        self.assertTrue(line.endswith(b"\n"))
        cmd, args = daemon.decode_request(line)
        self.assertEqual(cmd, "listing")
        self.assertEqual(args, ["0x491cc0", "--flag"])

    def test_response_round_trip_preserves_multiline_output(self) -> None:
        output = "line one\nline two\n"
        line = daemon.encode_response(True, 0, output)
        self.assertEqual(line.count(b"\n"), 1)  # newline-delimited framing holds
        resp = daemon.decode_response(line)
        self.assertEqual(resp, {"ok": True, "rc": 0, "output": output})


class DaemonSocketTests(unittest.TestCase):
    def test_daemon_and_eviction_share_one_socket_path(self) -> None:
        # The 2026-07 merge briefly left daemon.py binding .ghidra-query.sock while
        # ghidra_env eviction probed .ghidra-daemon.sock, silently disabling the
        # automatic eviction every one-shot/mutating open relies on.
        self.assertEqual(daemon.SOCKET_PATH, ghidra_env.socket_path())

    def test_pid_and_log_files_sit_next_to_the_socket(self) -> None:
        self.assertEqual(daemon.PID_PATH, daemon.SOCKET_PATH.with_suffix(".pid"))
        self.assertEqual(daemon.LOG_PATH, daemon.SOCKET_PATH.with_suffix(".log"))


class QueryRegistryTests(unittest.TestCase):
    EXPECTED = {
        "listing",
        "original-modules",
        "xrefs",
        "search",
        "linear-disasm",
        "raw-disasm",
        "jumptable",
        "decompile",
        "vtable-abi-evidence",
        "vtable-dump",
        "read-data",
        "function-slice",
        "func-sig",
        "field-xrefs",
        "string-oracle",
        "portprep",
    }

    def test_registry_serves_the_documented_command_surface(self) -> None:
        self.assertEqual(set(COMMANDS), self.EXPECTED)
        for name, handler in COMMANDS.items():
            self.assertTrue(callable(handler), name)


class XrefsParseTests(unittest.TestCase):
    def test_defaults_to_direction_to_with_thunk_hop(self) -> None:
        direction, addrs, thunk_hop, limit = parse_query(["0x581870"])
        self.assertEqual(direction, "to")
        self.assertEqual(addrs, [0x581870])
        self.assertTrue(thunk_hop)
        self.assertEqual(limit, 200)

    def test_parses_direction_keyword_and_flags(self) -> None:
        direction, addrs, thunk_hop, limit = parse_query(
            ["both", "0x581870", "0x4a3bc0", "--no-thunk-hop", "--limit", "10"]
        )
        self.assertEqual(direction, "both")
        self.assertEqual(addrs, [0x581870, 0x4A3BC0])
        self.assertFalse(thunk_hop)
        self.assertEqual(limit, 10)

    def test_limit_without_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_query(["0x581870", "--limit"])

    def test_non_hex_address_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_query(["from", "not-an-address"])


class ScreenshotDiscoveryTests(unittest.TestCase):
    def test_parses_xwininfo_tree_row(self) -> None:
        row = (
            '        0x4a00001 (has no name): ("imperialism.exe" "imperialism.exe")'
            "  2560x1440+0+0  +0+0"
        )
        m = WININFO_LINE_RE.match(row)
        self.assertIsNotNone(m)
        assert m is not None
        win_id, wm_class, width, height = m.groups()
        self.assertEqual(int(win_id, 16), 0x4A00001)
        self.assertEqual(wm_class, "imperialism.exe")
        self.assertEqual((int(width), int(height)), (2560, 1440))

    def test_ignores_rows_without_geometry(self) -> None:
        self.assertIsNone(WININFO_LINE_RE.match("  0x4a00002 (has no name): ()  "))


if __name__ == "__main__":
    unittest.main()
