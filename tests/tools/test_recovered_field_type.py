#!/usr/bin/env python3
"""Tests for tools.common.recovered_field_type."""

from __future__ import annotations

import unittest

from tools.common.recovered_field_type import (
    FieldKind,
    parse_field_type,
    to_csv_type,
)


class RecoveredFieldTypeTests(unittest.TestCase):
    def test_scalar_short(self) -> None:
        spec = parse_field_type("short")
        assert spec is not None
        self.assertEqual(spec.kind, FieldKind.SCALAR)
        self.assertEqual(spec.byte_length, 2)

    def test_explicit_int_pointer(self) -> None:
        spec = parse_field_type("int*")
        assert spec is not None
        self.assertEqual(spec.kind, FieldKind.POINTER)
        self.assertEqual(spec.byte_length, 4)

    def test_legacy_class_pointer(self) -> None:
        spec = parse_field_type("TCity")
        assert spec is not None
        self.assertEqual(spec.kind, FieldKind.POINTER)
        self.assertTrue(spec.is_class_pointer)

    def test_value_array_hex_count(self) -> None:
        spec = parse_field_type("short[0x17]")
        assert spec is not None
        self.assertEqual(spec.kind, FieldKind.VALUE_ARRAY)
        self.assertEqual(spec.count, 0x17)
        self.assertEqual(spec.byte_length, 0x17 * 2)

    def test_pointer_array_void(self) -> None:
        spec = parse_field_type("void*[0x3d]")
        assert spec is not None
        self.assertEqual(spec.kind, FieldKind.POINTER_ARRAY)
        self.assertEqual(spec.count, 0x3D)
        self.assertEqual(spec.byte_length, 0x3D * 4)

    def test_unsigned_char_array(self) -> None:
        spec = parse_field_type("unsigned char[2]")
        assert spec is not None
        self.assertEqual(spec.kind, FieldKind.VALUE_ARRAY)
        self.assertEqual(spec.byte_length, 2)

    def test_to_csv_type_emission(self) -> None:
        self.assertEqual(to_csv_type("void", is_ptr=True, array_count=0x3D), "void*[0x3d]")
        self.assertEqual(to_csv_type("TCity", is_ptr=True), "TCity")
        self.assertEqual(to_csv_type("int", is_ptr=True), "int*")


if __name__ == "__main__":
    unittest.main()
