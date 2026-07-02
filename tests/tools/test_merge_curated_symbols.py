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

    def test_drops_rows_colliding_with_source_vtable_addresses(self) -> None:
        # Any row at a `// VTABLE:` address (exported or curated orphan, even one
        # typed 'vtable') clobbers the marker-derived vtable entity; the merge
        # must drop it so a resync never re-introduces the collision.
        fieldnames = ["address", "name", "size", "type", "prototype"]
        curated = index_symbols_by_address(
            [
                {
                    "address": "649858",
                    "name": "TView::'vftable'",
                    "size": "4",
                    "type": "vtable",
                    "prototype": "",
                }
            ]
        )
        exported = [
            {
                "address": "64b7c8",
                "name": "CMcWindow::'vftable'",
                "size": "4",
                "type": "data",
                "prototype": "",
            },
            {
                "address": "412bf0",
                "name": "CObject::AssertValid",
                "size": "1",
                "type": "function",
                "prototype": "",
            },
        ]
        vtable_addrs = {0x649858, 0x64B7C8}
        merged, stats = merge_curated_symbols_csv(fieldnames, exported, curated, vtable_addrs)
        self.assertEqual([row["address"] for row in merged], ["412bf0"])
        self.assertEqual(stats.dropped_vtable_collisions, 2)
        self.assertEqual(stats.retained_orphans, 0)

    def test_preserves_curated_function_type_over_bare_label_export(self) -> None:
        # The DB deliberately keeps some jmp thunks as labels; the curated row's
        # function type/size must survive so stubgen keeps emitting the stub the
        # manual extern-thunk callsites link against.
        fieldnames = ["address", "name", "size", "type", "prototype"]
        curated = index_symbols_by_address(
            [
                {
                    "address": "49c950",
                    "name": "thunk_InitializeDirectSoundDeviceAndChannels",
                    "size": "5",
                    "type": "function",
                    "prototype": "undefined thunk_InitializeDirectSoundDeviceAndChannels()",
                }
            ]
        )
        exported = [
            {
                "address": "49c950",
                "name": "thunk_InitializeDirectSoundDeviceAndChannels",
                "size": "",
                "type": "global",
                "prototype": "",
            }
        ]
        merged, stats = merge_curated_symbols_csv(fieldnames, exported, curated)
        self.assertEqual(merged[0]["type"], "function")
        self.assertEqual(merged[0]["size"], "5")
        self.assertEqual(stats.preserved_function_types, 1)

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
