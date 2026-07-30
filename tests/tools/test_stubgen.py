#!/usr/bin/env python3
"""Tests for generated stub source shape."""

from __future__ import annotations

import unittest

from tools.stubgen import build_signature


class StubSignatureTests(unittest.TestCase):
    def test_uses_self_contained_void_prototype(self) -> None:
        self.assertEqual(
            build_signature("NoOpCallback", "void NoOpCallback(void)", False),
            "void NoOpCallback(void)",
        )

    def test_uses_self_contained_cdecl_void_prototype(self) -> None:
        self.assertEqual(
            build_signature("NoOpCallback", "void __cdecl NoOpCallback()", False),
            "void __cdecl NoOpCallback()",
        )

    def test_keeps_complex_prototypes_disabled(self) -> None:
        self.assertEqual(
            build_signature("CreateObject", "CObject* TStream::CreateObject(void)", False),
            "undefined4 CreateObject(void)",
        )


if __name__ == "__main__":
    unittest.main()
