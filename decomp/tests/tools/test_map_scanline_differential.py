#!/usr/bin/env python3
"""Contracts for the isolated map scanline retail differential."""

from __future__ import annotations

import unittest

from tools.runtime.map_scanline_differential import (
    FIXTURES,
    GRID_SIZE,
    MAP_WIDTH,
    SEA_SEGMENT_SIZE,
    TILE_COUNT,
    first_region_difference,
    initial_grid,
    region_array,
)


class MapScanlineDifferentialTests(unittest.TestCase):
    def test_fixture_matrix_covers_boundary_overlap_and_wrap(self) -> None:
        names = {fixture.name for fixture in FIXTURES}
        self.assertIn("left_boundary_parities", names)
        self.assertIn("shared_start_overlap", names)
        self.assertIn("shared_end_overlap", names)
        self.assertIn("horizontal_wrap", names)
        for fixture in FIXTURES:
            for segment in fixture.segments:
                self.assertEqual(len(segment.encode()), SEA_SEGMENT_SIZE)

    def test_complete_region_array_is_extracted_from_tile_records(self) -> None:
        grid = bytearray(initial_grid())
        grid[4] = 0x21
        grid[(TILE_COUNT - 1) * 0x24 + 4] = 0x42
        regions = region_array(bytes(grid))
        self.assertEqual(len(grid), GRID_SIZE)
        self.assertEqual(len(regions), TILE_COUNT)
        self.assertEqual(regions[0], 0x21)
        self.assertEqual(regions[-1], 0x42)

    def test_first_difference_reports_scanline_write_coordinates(self) -> None:
        retail = bytes(TILE_COUNT)
        recomp = bytearray(retail)
        divergent_index = MAP_WIDTH + 7
        recomp[divergent_index] = 0x2A
        self.assertEqual(
            first_region_difference(retail, bytes(recomp)),
            {
                "write_index": divergent_index,
                "row": 1,
                "column": 7,
                "retail": 0,
                "recomp": 0x2A,
            },
        )


if __name__ == "__main__":
    unittest.main()
