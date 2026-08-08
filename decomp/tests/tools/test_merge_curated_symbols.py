#!/usr/bin/env python3
"""Tests for tools.ghidra.merge_curated_symbols."""

from __future__ import annotations

import unittest

from tools.ghidra.merge_curated_symbols import (
    index_symbols_by_address,
    merge_curated_symbols_csv,
    resolve_embedded_owner_size,
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


class EmbeddedOwnerSizeTest(unittest.TestCase):
    """bd imperialism-decomp-777c: repaired Ghidra body sizes must reach curated rows.

    The embedded-owner override exists because Ghidra can promote labels inside a
    function's body to functions of their own, truncating the owner's recorded body. It
    used to let curation win unconditionally, which also reverted genuine repairs.
    """

    def test_repaired_larger_db_size_wins(self) -> None:
        # The exact regression: fix_function_bounds grew 0x43dbc0 to 29558 in the DB and
        # refresh-inventory put the stale 18464 back.
        self.assertIsNone(resolve_embedded_owner_size("29558", "18464"))
        self.assertIsNone(resolve_embedded_owner_size("47351", "41928"))

    def test_fragmented_smaller_db_size_keeps_curated(self) -> None:
        # The case the override was added for: an inner label split the owner's body.
        self.assertEqual(resolve_embedded_owner_size("12000", "41505"), "41505")

    def test_equal_sizes_leave_the_export_alone(self) -> None:
        self.assertIsNone(resolve_embedded_owner_size("100", "100"))

    def test_absent_curated_size_leaves_the_export_alone(self) -> None:
        self.assertIsNone(resolve_embedded_owner_size("100", ""))
        self.assertIsNone(resolve_embedded_owner_size("100", "   "))

    def test_non_numeric_size_falls_back_to_curation(self) -> None:
        self.assertEqual(resolve_embedded_owner_size("", "18464"), "18464")
        self.assertEqual(resolve_embedded_owner_size("unknown", "18464"), "18464")

    def test_merge_refreshes_size_while_preserving_curated_name(self) -> None:
        """The merge itself is not where the size was lost -- pin that so it stays true."""
        fields = ["address", "name", "symbol", "size", "type", "prototype", "provenance"]
        exported = [
            {
                "address": "43dbc0",
                "name": "ExportName",
                "symbol": "",
                "size": "29558",
                "type": "function",
                "prototype": "",
                "provenance": "",
            }
        ]
        curated = {
            0x43DBC0: {
                "address": "43dbc0",
                "name": "CuratedName",
                "symbol": "",
                "size": "18464",
                "type": "function",
                "prototype": "undefined f()",
                "provenance": "curated",
            }
        }
        rows, _stats = merge_curated_symbols_csv(fields, exported, curated, set(), set())
        self.assertEqual(rows[0]["name"], "CuratedName")
        self.assertEqual(rows[0]["size"], "29558")
