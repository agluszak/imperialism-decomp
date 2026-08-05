#!/usr/bin/env python3
"""Contracts for the isolated TurnEvent2 codec differential."""

from __future__ import annotations

import unittest

from tools.runtime.turn_event2_codec_differential import (
    BUILDER_FIXTURES,
    DECODER_FIXTURES,
    _entry,
)


class TurnEvent2CodecDifferentialTests(unittest.TestCase):
    def test_builder_matrix_covers_null_same_sparse_dense_and_threshold_sizes(self) -> None:
        names = {fixture.name for fixture in BUILDER_FIXTURES}
        for width in (1, 2, 4):
            self.assertIn(f"w{width}-n0-null", names)
            self.assertIn(f"w{width}-n12-same", names)
            self.assertIn(f"w{width}-n12-first", names)
            self.assertIn(f"w{width}-n12-dense", names)
        for width, count in ((1, 6), (2, 8), (4, 6)):
            self.assertIn(f"w{width}-n{count}-threshold-below", names)
            self.assertIn(f"w{width}-n{count}-threshold-equal", names)
            self.assertIn(f"w{width}-n{count}-threshold-above", names)

    def test_wire_entries_are_packed(self) -> None:
        self.assertEqual(_entry(1, 0x1234, 0x56), bytes.fromhex("341256"))
        self.assertEqual(_entry(2, 0x1234, -2), bytes.fromhex("3412feff"))
        self.assertEqual(_entry(3, 0x1234, 0x56789ABC), bytes.fromhex("3412bc9a7856"))

    def test_decoder_matrix_covers_modes_and_incomplete_trailing_records(self) -> None:
        names = {fixture.name for fixture in DECODER_FIXTURES}
        self.assertIn("mode0-empty", names)
        self.assertIn("invalid-mode", names)
        for mode, record_size in ((1, 3), (2, 4), (3, 6)):
            for remainder in range(record_size):
                self.assertIn(f"mode{mode}-one-rem{remainder}", names)


if __name__ == "__main__":
    unittest.main()
