#!/usr/bin/env python3
"""Tests for tools.workflow.reorder_marked_functions."""

from __future__ import annotations

import unittest

from tools.workflow.reorder_marked_functions import (
    MARKER_RE,
    PRAGMA_RE,
    FunctionBlock,
    is_leading_trivia,
    split_markers,
    find_block_starts,
    normalize_synthetic_nameref,
)


class MarkerRegexTests(unittest.TestCase):
    def test_matches_function_marker(self) -> None:
        match = MARKER_RE.match("// FUNCTION: IMPERIALISM 0x004E73F0")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("kind"), "FUNCTION")
        self.assertEqual(match.group("module"), "IMPERIALISM")
        self.assertEqual(match.group("offset"), "004E73F0")

    def test_matches_synthetic_marker(self) -> None:
        match = MARKER_RE.match("// SYNTHETIC: IMPERIALISM 0x00591EC0")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("kind"), "SYNTHETIC")

    def test_matches_stub_marker(self) -> None:
        match = MARKER_RE.match("// STUB: IMPERIALISM 0x00400000")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("kind"), "STUB")

    def test_matches_library_marker(self) -> None:
        match = MARKER_RE.match("// LIBRARY: IMPERIALISM 0x00606F73")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("kind"), "LIBRARY")

    def test_matches_template_marker(self) -> None:
        match = MARKER_RE.match("// TEMPLATE: IMPERIALISM 0x00500000")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("kind"), "TEMPLATE")

    def test_does_not_match_vtable(self) -> None:
        match = MARKER_RE.match("// VTABLE: IMPERIALISM 0x004B44D0")
        self.assertIsNone(match)

    def test_does_not_match_plain_comment(self) -> None:
        match = MARKER_RE.match("// just a comment")
        self.assertIsNone(match)


class PragmaRegexTests(unittest.TestCase):
    def test_matches_pragma_optimize(self) -> None:
        match = PRAGMA_RE.match('#pragma optimize("y", on)')
        self.assertIsNotNone(match)
        self.assertEqual(match.group("arg"), "y")

    def test_matches_empty_pragma(self) -> None:
        match = PRAGMA_RE.match('#pragma optimize("", on)')
        self.assertIsNotNone(match)
        self.assertEqual(match.group("arg"), "")

    def test_does_not_match_off(self) -> None:
        match = PRAGMA_RE.match('#pragma optimize("y", off)')
        self.assertIsNone(match)


class IsLeadingTriviaTests(unittest.TestCase):
    def test_blank_line(self) -> None:
        self.assertTrue(is_leading_trivia(""))
        self.assertTrue(is_leading_trivia("   "))

    def test_comment_line(self) -> None:
        self.assertTrue(is_leading_trivia("// some comment"))
        self.assertTrue(is_leading_trivia("  // indented"))

    def test_code_line(self) -> None:
        self.assertFalse(is_leading_trivia("int x = 5;"))
        self.assertFalse(is_leading_trivia("void Foo() {"))


class SplitMarkersTests(unittest.TestCase):
    def test_finds_multiple_markers(self) -> None:
        lines = [
            "// FUNCTION: IMPERIALISM 0x00400000",
            "void Foo() {}",
            "// FUNCTION: IMPERIALISM 0x00500000",
            "void Bar() {}",
        ]
        markers = split_markers(lines)
        self.assertIsNotNone(markers)
        self.assertEqual(len(markers), 2)
        self.assertEqual(markers[0], ("IMPERIALISM", 0x00400000, 0, "FUNCTION"))
        self.assertEqual(markers[1], ("IMPERIALISM", 0x00500000, 2, "FUNCTION"))

    def test_returns_none_for_single_marker(self) -> None:
        lines = [
            "// FUNCTION: IMPERIALISM 0x00400000",
            "void Foo() {}",
        ]
        self.assertIsNone(split_markers(lines))

    def test_returns_none_for_no_markers(self) -> None:
        lines = ["int x = 5;", "void Foo() {}"]
        self.assertIsNone(split_markers(lines))


class FindBlockStartsTests(unittest.TestCase):
    def test_attaches_leading_comments(self) -> None:
        lines = [
            "// leading comment for Foo",
            "// FUNCTION: IMPERIALISM 0x00400000",
            "void Foo() {}",
            "",
            "// FUNCTION: IMPERIALISM 0x00500000",
            "void Bar() {}",
        ]
        marker_indexes = [1, 4]
        starts = find_block_starts(lines, marker_indexes)
        self.assertEqual(starts[0], 0)
        self.assertEqual(starts[1], 3)

    def test_marker_without_leading_trivia(self) -> None:
        lines = [
            "// FUNCTION: IMPERIALISM 0x00400000",
            "void Foo() {}",
            "// FUNCTION: IMPERIALISM 0x00500000",
            "void Bar() {}",
        ]
        marker_indexes = [0, 2]
        starts = find_block_starts(lines, marker_indexes)
        self.assertEqual(starts[0], 0)
        self.assertEqual(starts[1], 2)


class NormalizeSyntheticNamerefTests(unittest.TestCase):
    def test_non_synthetic_unchanged(self) -> None:
        lines = ("// FUNCTION: IMPERIALISM 0x00400000\n", "void Foo() {}\n")
        result = normalize_synthetic_nameref(lines, "FUNCTION")
        self.assertEqual(result, lines)

    def test_synthetic_moves_detached_nameref(self) -> None:
        lines = (
            "// SYNTHETIC: IMPERIALISM 0x00591EC0\n",
            "\n",
            "// TFoo::`scalar deleting destructor'\n",
        )
        result = normalize_synthetic_nameref(lines, "SYNTHETIC")
        self.assertEqual(result[1], "// TFoo::`scalar deleting destructor'\n")

    def test_synthetic_already_attached_unchanged(self) -> None:
        lines = (
            "// SYNTHETIC: IMPERIALISM 0x00591EC0\n",
            "// TFoo::`scalar deleting destructor'\n",
        )
        result = normalize_synthetic_nameref(lines, "SYNTHETIC")
        self.assertEqual(result, lines)


if __name__ == "__main__":
    unittest.main()
