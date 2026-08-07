#!/usr/bin/env python3
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from tools.mfc.library_pairing_identities import (
    select_exact_identities,
    write_identity_source,
)


def row(address: str, symbol: str, kind: str = "unique", confidence: str = "high"):
    return {
        "address": address,
        "symbol": symbol,
        "library": "libcmt",
        "member": "sample.obj",
        "match_kind": kind,
        "confidence": confidence,
    }


class ExactIdentitySelectionTests(unittest.TestCase):
    def test_selects_only_unique_identity_on_both_sides(self) -> None:
        decisions = select_exact_identities([row("0x401000", "_puts")], {"_puts": 1})
        self.assertEqual(decisions[0].status, "selected")

    def test_duplicate_original_symbol_stays_ambiguous(self) -> None:
        decisions = select_exact_identities(
            [row("0x401000", "_same"), row("0x402000", "_same")], {"_same": 1}
        )
        self.assertEqual({d.status for d in decisions}, {"ambiguous-original-symbol"})

    def test_duplicate_recomp_symbol_stays_ambiguous(self) -> None:
        decisions = select_exact_identities([row("0x401000", "_same")], {"_same": 2})
        self.assertEqual(decisions[0].status, "ambiguous-recomp-symbol")

    def test_missing_recomp_symbol_is_reported(self) -> None:
        decisions = select_exact_identities([row("0x401000", "_gone")], {})
        self.assertEqual(decisions[0].status, "missing-recomp-symbol")

    def test_oracle_ambiguity_is_never_promoted(self) -> None:
        decisions = select_exact_identities(
            [row("0x401000", "_a", "ambiguous", "review")], {"_a": 1}
        )
        self.assertEqual(decisions[0].status, "oracle-ambiguous-review")

    def test_unique_via_existing_is_not_independent_identity(self) -> None:
        decisions = select_exact_identities(
            [row("0x401000", "_a", "unique-via-existing", "high")], {"_a": 1}
        )
        self.assertEqual(decisions[0].status, "oracle-unique-via-existing-high")

    def test_output_contains_only_selected_rows(self) -> None:
        decisions = select_exact_identities(
            [row("0x401000", "_yes"), row("0x402000", "_no")],
            {"_yes": 1},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "identities.csv"
            write_identity_source(path, decisions)
            with path.open(newline="", encoding="utf-8") as fd:
                rows = list(csv.DictReader(fd, delimiter="|"))
        self.assertEqual(
            rows,
            [{"address": "0x00401000", "symbol": "_yes", "type": "function"}],
        )


if __name__ == "__main__":
    unittest.main()
