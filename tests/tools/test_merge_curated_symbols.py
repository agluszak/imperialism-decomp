#!/usr/bin/env python3
"""Tests for tools.ghidra.merge_curated_symbols."""

from __future__ import annotations

import unittest

from tools.ghidra.merge_curated_symbols import (
    index_symbols_by_address,
    merge_curated_symbols_csv,
)


class MergeCuratedSymbolsTests(unittest.TestCase):
    def test_preserves_curated_name_and_prototype(self) -> None:
        fieldnames = ["address", "name", "size", "type", "prototype"]
        curated = index_symbols_by_address(
            [
                {
                    "address": "412bf0",
                    "name": "CObject::AssertValid",
                    "size": "1",
                    "type": "function",
                    "prototype": "void AssertValid() const",
                }
            ]
        )
        exported = [
            {
                "address": "412bf0",
                "name": "CDocument::ConstructTTaskBaseState",
                "size": "1",
                "type": "function",
                "prototype": "undefined __thiscall ConstructTTaskBaseState(void)",
            },
            {
                "address": "401d61",
                "name": "TControl::thunk_ForwardCityDialogParamToChildSlot48",
                "size": "5",
                "type": "function",
                "prototype": "undefined __thiscall thunk_ForwardCityDialogParamToChildSlot48(void)",
            },
        ]
        merged, stats = merge_curated_symbols_csv(fieldnames, exported, curated)
        self.assertEqual(merged[0]["name"], "CObject::AssertValid")
        self.assertEqual(merged[0]["prototype"], "void AssertValid() const")
        self.assertEqual(merged[1]["name"], exported[1]["name"])
        self.assertEqual(stats.preserved_names, 1)
        self.assertEqual(stats.preserved_prototypes, 1)
        self.assertEqual(stats.new_from_export, 1)
        self.assertEqual(stats.retained_orphans, 0)

    def test_retains_curated_only_rows(self) -> None:
        fieldnames = ["address", "name", "size", "type", "prototype"]
        curated = index_symbols_by_address(
            [
                {
                    "address": "deadbeef",
                    "name": "CuratedOnlySymbol",
                    "size": "4",
                    "type": "function",
                    "prototype": "void CuratedOnlySymbol(void)",
                }
            ]
        )
        merged, stats = merge_curated_symbols_csv(fieldnames, [], curated)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["name"], "CuratedOnlySymbol")
        self.assertEqual(stats.retained_orphans, 1)


if __name__ == "__main__":
    unittest.main()
