#!/usr/bin/env python3
"""Contracts for `just inventory-drop`, and for what refresh-inventory must NOT do.

The decision logic is pure so it can be tested without a Ghidra DB: `classify` takes the
inventory rows, the DB's entity addresses and the source-claimed addresses, and returns a
verdict per address.
"""

from __future__ import annotations

import unittest

from tools.ghidra.inventory_drop import classify
from tools.ghidra.merge_curated_symbols import orphan_is_unclaimed


ROWS = {
    0x004C8C09: {"address": "4c8c09", "name": "UpdateCityViewCountControl", "provenance": ""},
    0x005EDE75: {"address": "5ede75", "name": "__seh_longjmp_unwind@4", "provenance": ""},
    0x00561B10: {"address": "561b10", "name": "TPortZone::QueryFlagD", "provenance": ""},
}


class ClassifyTests(unittest.TestCase):
    def test_gone_from_the_db_and_unclaimed_is_droppable(self) -> None:
        verdict = classify(0x004C8C09, ROWS, db_addresses=set(), claimed_addresses=set())
        self.assertTrue(verdict.droppable)
        self.assertIn("no DB entity", verdict.reason)

    def test_still_in_the_db_is_kept(self) -> None:
        """The case that made a blanket export-diff delete unsound.

        __seh_longjmp_unwind@4 and the _$E3xx EH thunks are in the DB and in no export;
        deleting them on absence-from-export removed nine live entities.
        """
        verdict = classify(
            0x005EDE75, ROWS, db_addresses={0x005EDE75}, claimed_addresses=set()
        )
        self.assertFalse(verdict.droppable)
        self.assertIn("still has a function or label", verdict.reason)

    def test_source_claimed_is_kept_unless_overridden(self) -> None:
        kept = classify(
            0x00561B10, ROWS, db_addresses=set(), claimed_addresses={0x00561B10}
        )
        self.assertFalse(kept.droppable)
        self.assertIn("--allow-claimed", kept.reason)
        forced = classify(
            0x00561B10,
            ROWS,
            db_addresses=set(),
            claimed_addresses={0x00561B10},
            allow_claimed=True,
        )
        self.assertTrue(forced.droppable)

    def test_an_address_with_no_row_is_not_droppable(self) -> None:
        verdict = classify(0x00999999, ROWS, db_addresses=set(), claimed_addresses=set())
        self.assertFalse(verdict.droppable)
        self.assertIn("no inventory row", verdict.reason)


class OrphanReportingTests(unittest.TestCase):
    """orphan_is_unclaimed feeds a report; it must never be wired to a delete."""

    def test_unvouched_orphan_is_reportable(self) -> None:
        self.assertTrue(orphan_is_unclaimed({"address": "4c8c09", "provenance": ""}, set()))

    def test_a_source_claim_or_any_provenance_vouches_for_the_row(self) -> None:
        self.assertFalse(
            orphan_is_unclaimed({"address": "4c8c09", "provenance": ""}, {0x4C8C09})
        )
        for provenance in ("curated", "rtti", "msvc500_library_oracle", "mac_oracle"):
            self.assertFalse(
                orphan_is_unclaimed({"address": "4c8c09", "provenance": provenance}, set()),
                provenance,
            )

    def test_an_unparsable_address_is_never_reported(self) -> None:
        self.assertFalse(orphan_is_unclaimed({"address": "", "provenance": ""}, set()))


if __name__ == "__main__":
    unittest.main()
