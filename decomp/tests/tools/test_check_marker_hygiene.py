"""Both-directions coverage for the // FUNCTION and // GLOBAL marker gates."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from tools.workflow.check_marker_hygiene import (
    FUNCTION_MARKER_RE,
    GLOBAL_MARKER_RE,
    is_declaration_line,
    main,
    normalize_offset,
)


def run_gate(source: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.cpp"
        path.write_text(source, encoding="utf-8")
        argv = ["check_marker_hygiene", "--paths", str(path)]
        with mock.patch.object(sys, "argv", argv):
            return main()


class NormalizeOffsetTests(unittest.TestCase):
    def test_width_and_case_fold(self) -> None:
        self.assertEqual(normalize_offset("0x004DFD30"), "0x4dfd30")
        self.assertEqual(normalize_offset("0x4dfd30"), "0x4dfd30")

    def test_all_zero_address(self) -> None:
        self.assertEqual(normalize_offset("0x00000000"), "0x0")


class DeclarationLineTests(unittest.TestCase):
    def test_real_declaration_accepted(self) -> None:
        self.assertTrue(is_declaration_line("void Foo::Bar() {"))

    def test_blank_and_comment_lines_rejected(self) -> None:
        self.assertFalse(is_declaration_line(""))
        self.assertFalse(is_declaration_line("   "))
        self.assertFalse(is_declaration_line("// note"))
        self.assertFalse(is_declaration_line("/* block */"))


class MarkerGateTests(unittest.TestCase):
    def test_clean_markers_pass(self) -> None:
        self.assertEqual(
            run_gate(
                "// FUNCTION: IMPERIALISM 0x00401000\n"
                "void Foo::Bar() {}\n"
                "// GLOBAL: IMPERIALISM 0x00601000\n"
                "int g_value;\n"
            ),
            0,
        )

    def test_marker_not_adjacent_to_declaration_fails(self) -> None:
        self.assertEqual(
            run_gate(
                "// FUNCTION: IMPERIALISM 0x00401000\n"
                "// stray comment\n"
                "void Foo::Bar() {}\n"
            ),
            1,
        )

    def test_duplicate_function_address_fails(self) -> None:
        self.assertEqual(
            run_gate(
                "// FUNCTION: IMPERIALISM 0x00401000\n"
                "void Foo::Bar() {}\n"
                "// FUNCTION: IMPERIALISM 0x401000\n"
                "void Foo::Baz() {}\n"
            ),
            1,
        )

    def test_duplicate_global_address_fails(self) -> None:
        self.assertEqual(
            run_gate(
                "// GLOBAL: IMPERIALISM 0x00601000\n"
                "int g_a;\n"
                "// GLOBAL: IMPERIALISM 0x601000\n"
                "int g_b;\n"
            ),
            1,
        )


class MarkerRegexTests(unittest.TestCase):
    def test_function_marker_shape(self) -> None:
        self.assertIsNotNone(FUNCTION_MARKER_RE.match("// FUNCTION: IMPERIALISM 0x00401000"))
        self.assertIsNone(FUNCTION_MARKER_RE.match("// GLOBAL: IMPERIALISM 0x00401000"))

    def test_global_marker_shape(self) -> None:
        self.assertIsNotNone(GLOBAL_MARKER_RE.match("// GLOBAL: IMPERIALISM 0x00601000"))
        self.assertIsNone(GLOBAL_MARKER_RE.match("// FUNCTION: IMPERIALISM 0x00601000"))


if __name__ == "__main__":
    unittest.main()
