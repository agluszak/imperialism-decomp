#!/usr/bin/env python3
"""Tests for tools.workflow.check_marker_hygiene."""

from __future__ import annotations

import unittest

from tools.workflow.check_marker_hygiene import (
    FUNCTION_MARKER_RE,
    is_declaration_line,
    normalize_offset,
)


class NormalizeOffsetTests(unittest.TestCase):
    def test_with_0x_prefix(self) -> None:
        self.assertEqual(normalize_offset("0x004E73F0"), "0x004e73f0")

    def test_without_prefix(self) -> None:
        self.assertEqual(normalize_offset("004E73F0"), "0x004e73f0")

    def test_already_lowercase(self) -> None:
        self.assertEqual(normalize_offset("0xabcdef"), "0xabcdef")

    def test_short_value(self) -> None:
        self.assertEqual(normalize_offset("0xFF"), "0xff")


class IsDeclarationLineTests(unittest.TestCase):
    def test_empty_line_is_not_declaration(self) -> None:
        self.assertFalse(is_declaration_line(""))

    def test_whitespace_only_is_not_declaration(self) -> None:
        self.assertFalse(is_declaration_line("   "))

    def test_comment_is_not_declaration(self) -> None:
        self.assertFalse(is_declaration_line("// some comment"))
        self.assertFalse(is_declaration_line("  // indented comment"))

    def test_function_declaration_is_declaration(self) -> None:
        self.assertTrue(is_declaration_line("void Foo();"))

    def test_variable_declaration_is_declaration(self) -> None:
        self.assertTrue(is_declaration_line("int x = 42;"))

    def test_preprocessor_is_declaration(self) -> None:
        self.assertTrue(is_declaration_line("#include <stdio.h>"))


class FunctionMarkerRegexTests(unittest.TestCase):
    def test_matches_standard_function_marker(self) -> None:
        line = "// FUNCTION: IMPERIALISM 0x004E73F0"
        match = FUNCTION_MARKER_RE.match(line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("module"), "IMPERIALISM")
        self.assertEqual(match.group("offset"), "0x004E73F0")

    def test_matches_with_extra_spacing(self) -> None:
        line = "  //  FUNCTION :  IMPERIALISM  0x004E73F0"
        match = FUNCTION_MARKER_RE.match(line)
        self.assertIsNotNone(match)

    def test_matches_without_0x_prefix(self) -> None:
        line = "// FUNCTION: IMPERIALISM 004E73F0"
        match = FUNCTION_MARKER_RE.match(line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("offset"), "004E73F0")

    def test_does_not_match_vtable_marker(self) -> None:
        line = "// VTABLE: IMPERIALISM 0x004E73F0"
        match = FUNCTION_MARKER_RE.match(line)
        self.assertIsNone(match)

    def test_does_not_match_plain_comment(self) -> None:
        line = "// This is a regular comment"
        match = FUNCTION_MARKER_RE.match(line)
        self.assertIsNone(match)

    def test_does_not_match_code(self) -> None:
        line = "int x = 5;"
        match = FUNCTION_MARKER_RE.match(line)
        self.assertIsNone(match)


if __name__ == "__main__":
    unittest.main()
