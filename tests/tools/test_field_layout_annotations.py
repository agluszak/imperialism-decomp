#!/usr/bin/env python3
"""Tests for field layout annotation parsing."""

from __future__ import annotations

import unittest

from tools.common.field_layout_annotations import (
    build_name_offset_hints,
    field_line_index,
    is_pad_field,
    parse_layout_status_comment,
    resolve_field_offset_from_lines,
)


class FieldLayoutAnnotationTests(unittest.TestCase):
    def test_same_line_offset(self) -> None:
        lines = ["  short needCapA6; // +0xa6"]
        idx = field_line_index(lines, "needCapA6")
        off, source = resolve_field_offset_from_lines(lines, "needCapA6", idx)
        self.assertEqual(off, 0xA6)
        self.assertEqual(source, "same_line")

    def test_block_range_prev_line(self) -> None:
        lines = [
            "  // 0xe4..0x1d8 — owned order objects",
            "  void* orderSlotsE4[0x3d];",
        ]
        idx = field_line_index(lines, "orderSlotsE4")
        off, source = resolve_field_offset_from_lines(lines, "orderSlotsE4", idx)
        self.assertEqual(off, 0xE4)
        self.assertEqual(source, "prev_block_range")

    def test_base_diagram_range_does_not_assign(self) -> None:
        lines = [
            "  // 0x04..0x90 (identity strings) now live on the TCountry base.",
            "  TForeignMinister* foreignMinister;",
        ]
        idx = field_line_index(lines, "foreignMinister")
        off, source = resolve_field_offset_from_lines(lines, "foreignMinister", idx)
        self.assertIsNone(off)
        self.assertEqual(source, "missing")

    def test_layout_status_comment(self) -> None:
        lines = ["// LAYOUT: RECOVERED", "class TCity {"]
        status = parse_layout_status_comment(lines)
        self.assertIsNotNone(status)
        self.assertEqual(status.value, "recovered")

    def test_pad_fields(self) -> None:
        self.assertTrue(is_pad_field("pad_a1"))
        self.assertTrue(is_pad_field("padding_00"))
        self.assertFalse(is_pad_field("fieldB6"))

    def test_multiline_comment_block(self) -> None:
        lines = [
            "  // +0x7e..+0xac — per-resource reserved amounts",
            "  // (entry 0x13 doubles as labor reserve).",
            "  short reservedByType7e[0x17];",
        ]
        idx = field_line_index(lines, "reservedByType7e")
        off, source = resolve_field_offset_from_lines(lines, "reservedByType7e", idx)
        self.assertEqual(off, 0x7E)
        self.assertEqual(source, "prev_block_range")

        lines = ["  short field04; // +0x04", "  short field06; // +0x06"]
        hints = build_name_offset_hints(lines)
        self.assertEqual(hints["field04"], 0x04)
        self.assertEqual(hints["field06"], 0x06)


if __name__ == "__main__":
    unittest.main()
