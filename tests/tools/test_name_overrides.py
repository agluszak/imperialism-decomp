#!/usr/bin/env python3
"""Tests for tools.common.name_overrides."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.common.name_overrides import sanitize_override_field, parse_name_overrides


class SanitizeOverrideFieldTests(unittest.TestCase):
    def test_collapses_whitespace(self) -> None:
        self.assertEqual(sanitize_override_field("  foo   bar  "), "foo bar")

    def test_replaces_pipes(self) -> None:
        self.assertEqual(sanitize_override_field("foo|bar|baz"), "foo bar baz")

    def test_empty_string(self) -> None:
        self.assertEqual(sanitize_override_field(""), "")

    def test_single_word(self) -> None:
        self.assertEqual(sanitize_override_field("Hello"), "Hello")

    def test_mixed_pipes_and_spaces(self) -> None:
        self.assertEqual(sanitize_override_field("  a | b  | c  "), "a b c")


class ParseNameOverridesTests(unittest.TestCase):
    def test_parses_valid_csv(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("address|name|prototype\n")
            f.write("0x004E73F0|MyFunc|void MyFunc(int x)\n")
            f.write("0x00500000|OtherFunc|int OtherFunc()\n")
            path = Path(f.name)

        result = parse_name_overrides(path)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0x004E73F0], ("MyFunc", "void MyFunc(int x)"))
        self.assertEqual(result[0x00500000], ("OtherFunc", "int OtherFunc()"))
        path.unlink()

    def test_missing_file_returns_empty(self) -> None:
        result = parse_name_overrides(Path("/nonexistent/file.csv"))
        self.assertEqual(result, {})

    def test_skips_rows_without_address(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("address|name|prototype\n")
            f.write("|NoAddr|void NoAddr()\n")
            f.write("0x100|HasAddr|int HasAddr()\n")
            path = Path(f.name)

        result = parse_name_overrides(path)
        self.assertEqual(len(result), 1)
        self.assertIn(0x100, result)
        path.unlink()

    def test_sanitizes_name_and_prototype(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("address|name|prototype\n")
            f.write("0x100|  My  Func  |  void  Func(int  x)  \n")
            path = Path(f.name)

        result = parse_name_overrides(path)
        name, proto = result[0x100]
        self.assertEqual(name, "My Func")
        self.assertEqual(proto, "void Func(int x)")
        path.unlink()


if __name__ == "__main__":
    unittest.main()
