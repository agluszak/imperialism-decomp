#!/usr/bin/env python3
"""Golden tests for header-driven recovered_fields generation."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.ghidra.gen_recovered_fields_from_headers import extract_class_rows, load_layout_bases

REPO = repo_root_from_file(__file__)
INCLUDE_GAME = REPO / "include" / "game"

# Pilot fields the generator must place correctly from live headers. TCity's raw
# fieldB6/orderSlotsE4 regions were since recovered into named members. TGreatPower
# rows without an offset-comment hint were dropped: their absolute offsets came from
# the dormant config/classes/ manifest base_offset (TCountry-inlined +0x90), which
# no longer exists; only hint-anchored fields (e.g. `city` +0x894) stay verifiable.
PILOT_ROWS: dict[tuple[str, str], tuple[int, str]] = {
    ("TCity", "cityStockCottonB6"): (0xB6, "short"),
    ("TCity", "cityStockGoldE2"): (0xE2, "short"),
    ("TCity", "ownerNationAc"): (0xAC, "TGreatPower"),
    ("TCity", "productionOrderTable1dc"): (0x1DC, "short[0x10]"),
    ("TCity", "trackedOrderList270"): (0x270, "TSortedList"),
    ("TGreatPower", "city"): (0x894, "TCity"),
}


class GenRecoveredFieldsFromHeadersTests(unittest.TestCase):
    def test_pilot_offsets_match_curated_csv(self) -> None:
        layout_bases = load_layout_bases()
        for (class_name, field_name), (expected_off, expected_type) in PILOT_ROWS.items():
            path = INCLUDE_GAME / f"{class_name}.h"
            rows = extract_class_rows(path, class_name, layout_bases)
            by_name = {row.field_name: row for row in rows}
            self.assertIn(field_name, by_name, f"{class_name}.{field_name} missing from generator output")
            row = by_name[field_name]
            self.assertEqual(row.offset, expected_off, f"{class_name}.{field_name} offset")
            self.assertEqual(row.field_type, expected_type, f"{class_name}.{field_name} type")


if __name__ == "__main__":
    unittest.main()
