#!/usr/bin/env python3
"""Tests for the relocation-masked library identity matcher.

Uses the vendored libcmt.lib where present (known-answer checks against rand.obj /
memmove.obj) and pure-logic tests otherwise, so the suite still runs without the
vendored archives.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.mfc.coff import _trim_padding, mask_bytes, parse_library
from tools.mfc.build_library_oracle import LibraryIndex, classify, friendly_name_and_prototype
from tools.mfc.coff import LibraryFunction

REPO = repo_root_from_file(__file__, levels_up=2)
LIBCMT = REPO / "vendor" / "msvc500" / "lib" / "libcmt.lib"


class MaskAndTrimTests(unittest.TestCase):
    def test_mask_zeroes_four_bytes(self) -> None:
        body = bytes(range(16))
        masked = mask_bytes(body, (4,))
        self.assertEqual(masked[4:8], b"\x00\x00\x00\x00")
        self.assertEqual(masked[:4], body[:4])
        self.assertEqual(masked[8:], body[8:])

    def test_trim_trailing_padding(self) -> None:
        body, dropped = _trim_padding(b"\x55\x8b\xec\xc3\x90\x90\xcc")
        self.assertEqual(body, b"\x55\x8b\xec\xc3")
        self.assertEqual(dropped, 3)

    def test_trim_keeps_non_padding(self) -> None:
        body, dropped = _trim_padding(b"\x55\x8b\xec\xc3")
        self.assertEqual(dropped, 0)


class NameExtractionTests(unittest.TestCase):
    def test_cpp_qualified(self) -> None:
        name, proto = friendly_name_and_prototype("?AddBitmap@CToolBarCtrl@@QAEHHPAVCBitmap@@@Z")
        self.assertEqual(name, "CToolBarCtrl::AddBitmap")
        self.assertIn("CToolBarCtrl::AddBitmap", proto)

    def test_operator(self) -> None:
        name, _ = friendly_name_and_prototype("??3CObject@@SGXPAX@Z")
        self.assertEqual(name, "CObject::operator delete")

    def test_c_symbol(self) -> None:
        self.assertEqual(friendly_name_and_prototype("_atexit"), ("atexit", ""))
        self.assertEqual(friendly_name_and_prototype("__ftol"), ("_ftol", ""))

    def test_function_pointer_signature_falls_back(self) -> None:
        name, _ = friendly_name_and_prototype("?_set_new_handler@@YAP6AHI@ZP6AHI@Z@Z")
        self.assertEqual(name, "_set_new_handler")


class ClassifyTests(unittest.TestCase):
    def _index(self, *funcs: LibraryFunction) -> LibraryIndex:
        idx = LibraryIndex()
        for f in funcs:
            idx.add("libcmt", f)
        return idx

    def test_unique_match(self) -> None:
        f = LibraryFunction("rand.obj", "_rand", 8, b"\x33\xc0\xc3\x90\x90\x90\x90\x90", ())
        idx = self._index(f)
        result = classify(0x1000, [f], idx, "", 8)
        self.assertEqual(result.match_kind, "unique")
        self.assertEqual(result.symbol, "_rand")
        self.assertEqual(result.confidence, "high")

    def test_ambiguous_resolved_by_existing(self) -> None:
        a = LibraryFunction("a.obj", "_a", 8, b"\x33\xc0\xc3\x90\x90\x90\x90\x90", ())
        b = LibraryFunction("b.obj", "_b", 8, b"\x33\xc0\xc3\x90\x90\x90\x90\x90", ())
        idx = self._index(a, b)
        result = classify(0x1000, [a, b], idx, "_b", 8)
        self.assertEqual(result.match_kind, "unique-via-existing")
        self.assertEqual(result.symbol, "_b")

    def test_ambiguous_unresolved(self) -> None:
        a = LibraryFunction("a.obj", "_a", 8, b"\x33\xc0\xc3\x90\x90\x90\x90\x90", ())
        b = LibraryFunction("b.obj", "_b", 8, b"\x33\xc0\xc3\x90\x90\x90\x90\x90", ())
        idx = self._index(a, b)
        result = classify(0x1000, [a, b], idx, "", 8)
        self.assertEqual(result.match_kind, "ambiguous")
        self.assertEqual(result.candidate_count, 2)


@unittest.skipUnless(LIBCMT.is_file(), "vendored libcmt.lib not present")
class LibcmtKnownAnswerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.funcs = {(f.member, f.symbol): f for f in parse_library(LIBCMT)}

    def test_rand_srand_sizes(self) -> None:
        # Trailing-padding-trimmed sizes must match Ghidra's function sizes.
        self.assertEqual(self.funcs[("rand.obj", "_srand")].size, 13)
        self.assertEqual(self.funcs[("rand.obj", "_rand")].size, 45)

    def test_memmove_not_truncated_at_internal_label(self) -> None:
        # memmove.obj is one COMDAT section full of internal jump-table labels;
        # the function must span the whole section, not stop at the first label.
        self.assertGreater(self.funcs[("memmove.obj", "_memmove")].size, 700)


if __name__ == "__main__":
    unittest.main()
