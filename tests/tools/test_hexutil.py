#!/usr/bin/env python3
"""Tests for tools.common.hexutil."""

from __future__ import annotations

import unittest

from tools.common.hexutil import parse_hex_address


class ParseHexAddressTests(unittest.TestCase):
    def test_with_0x_prefix(self) -> None:
        self.assertEqual(parse_hex_address("0x004E73F0"), 0x004E73F0)

    def test_without_prefix(self) -> None:
        self.assertEqual(parse_hex_address("004E73F0"), 0x004E73F0)

    def test_lowercase(self) -> None:
        self.assertEqual(parse_hex_address("0x004e73f0"), 0x004E73F0)

    def test_uppercase(self) -> None:
        self.assertEqual(parse_hex_address("0X004E73F0"), 0x004E73F0)

    def test_whitespace_stripped(self) -> None:
        self.assertEqual(parse_hex_address("  0x004E73F0  "), 0x004E73F0)

    def test_short_address(self) -> None:
        self.assertEqual(parse_hex_address("0xFF"), 0xFF)

    def test_zero(self) -> None:
        self.assertEqual(parse_hex_address("0x0"), 0)

    def test_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_hex_address("not_hex")


if __name__ == "__main__":
    unittest.main()
