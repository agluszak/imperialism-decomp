#!/usr/bin/env python3
"""Tests for tools.workflow.normalize_reccmp_markers."""

from __future__ import annotations

import unittest

from tools.workflow.normalize_reccmp_markers import (
    normalize_extra,
    normalize_line,
    normalize_offset,
)


class NormalizeOffsetTests(unittest.TestCase):
    def test_with_prefix(self) -> None:
        self.assertEqual(normalize_offset("0x004E73F0"), "0x004e73f0")

    def test_without_prefix(self) -> None:
        self.assertEqual(normalize_offset("004E73F0"), "0x004e73f0")

    def test_already_normalized(self) -> None:
        self.assertEqual(normalize_offset("0xabcdef"), "0xabcdef")


class NormalizeExtraTests(unittest.TestCase):
    def test_none_returns_empty(self) -> None:
        self.assertEqual(normalize_extra(None), "")

    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(normalize_extra("  "), "")

    def test_preserves_content_with_leading_space(self) -> None:
        self.assertEqual(normalize_extra("  some extra info  "), " some extra info")

    def test_simple_text(self) -> None:
        self.assertEqual(normalize_extra("note"), " note")


class NormalizeLineTests(unittest.TestCase):
    def test_function_marker_normalized(self) -> None:
        line = "// FUNCTION: imperialism 0x004E73F0\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// FUNCTION: IMPERIALISM 0x004e73f0\n")
        self.assertTrue(changed)

    def test_already_normalized_unchanged(self) -> None:
        line = "// FUNCTION: IMPERIALISM 0x004e73f0\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, line)
        self.assertFalse(changed)

    def test_stub_marker(self) -> None:
        line = "// stub: imperialism 0xFF\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// STUB: IMPERIALISM 0xff\n")
        self.assertTrue(changed)

    def test_vtable_marker(self) -> None:
        line = "// vtable: imperialism 0x004B44D0\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// VTABLE: IMPERIALISM 0x004b44d0\n")
        self.assertTrue(changed)

    def test_synthetic_marker_uppercased(self) -> None:
        line = "// SYNTHETIC: IMPERIALISM 0x00591EC0\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// SYNTHETIC: IMPERIALISM 0x00591ec0\n")
        self.assertTrue(changed)

    def test_synthetic_marker_already_normalized(self) -> None:
        line = "// SYNTHETIC: IMPERIALISM 0x00591ec0\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, line)
        self.assertFalse(changed)

    def test_manual_override_pseudo_marker(self) -> None:
        line = "// MANUAL_OVERRIDE_ADDR IMPERIALISM 0x00500000\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// MANUAL_OVERRIDE_ADDR IMPERIALISM 0x00500000\n")
        self.assertFalse(changed)

    def test_manual_override_with_colon_removes_colon(self) -> None:
        line = "// MANUAL_OVERRIDE_ADDR: IMPERIALISM 0x00500000\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// MANUAL_OVERRIDE_ADDR IMPERIALISM 0x00500000\n")
        self.assertTrue(changed)

    def test_non_marker_line_unchanged(self) -> None:
        line = "int x = 5;\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, line)
        self.assertFalse(changed)

    def test_regular_comment_unchanged(self) -> None:
        line = "// This is a regular comment\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, line)
        self.assertFalse(changed)

    def test_extra_content_preserved(self) -> None:
        line = "// FUNCTION: IMPERIALISM 0x004e73f0 TFoo::Bar\n"
        normalized, changed = normalize_line(line)
        self.assertIn("TFoo::Bar", normalized)
        self.assertFalse(changed)

    def test_global_marker(self) -> None:
        line = "// global: imperialism 0x100\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// GLOBAL: IMPERIALISM 0x100\n")
        self.assertTrue(changed)

    def test_library_marker(self) -> None:
        line = "// library: imperialism 0xABC\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// LIBRARY: IMPERIALISM 0xabc\n")
        self.assertTrue(changed)

    def test_string_marker(self) -> None:
        line = "// string: imperialism 0xDEF\n"
        normalized, changed = normalize_line(line)
        self.assertEqual(normalized, "// STRING: IMPERIALISM 0xdef\n")
        self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()
