"""Both-directions coverage for the symbols.csv integrity gate helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from tools.workflow.check_symbols_integrity import (
    check_function_overlaps,
    load_function_ranges,
    read_overlap_allowlist,
)


def row(addr: str, size: str, name: str, typ: str = "function") -> dict[str, str]:
    return {"address": addr, "size": size, "name": name, "type": typ}


class LoadFunctionRangesTests(unittest.TestCase):
    def test_function_rows_become_ranges(self) -> None:
        ranges = load_function_ranges(
            [row("0x1000", "16", "Foo"), row("0x2000", "", "GData", "global")]
        )
        self.assertEqual(ranges, [(0x1000, 0x1010, "Foo")])

    def test_nonpositive_and_unparseable_rows_skipped(self) -> None:
        ranges = load_function_ranges(
            [row("0x1000", "0", "Zero"), row("0xzz", "8", "Bad"), row("0x3000", "8", "Ok")]
        )
        self.assertEqual(ranges, [(0x3000, 0x3008, "Ok")])


class OverlapTests(unittest.TestCase):
    RANGES = [
        (0x1000, 0x1100, "Outer"),
        (0x1040, 0x1060, "SwallowedInner"),
        (0x2000, 0x2010, "Clean"),
    ]

    def test_unlisted_overlap_is_violation(self) -> None:
        violations = check_function_overlaps(self.RANGES, set())
        self.assertEqual(len(violations), 1)
        self.assertIn("0x1040", violations[0])
        self.assertIn("SwallowedInner", violations[0])

    def test_allowlisted_overlap_passes(self) -> None:
        violations = check_function_overlaps(self.RANGES, {(0x1000, 0x1040)})
        self.assertEqual(violations, [])

    def test_disjoint_ranges_pass(self) -> None:
        violations = check_function_overlaps(
            [(0x1000, 0x1010, "A"), (0x1010, 0x1020, "B")], set()
        )
        self.assertEqual(violations, [])


class OverlapAllowlistTests(unittest.TestCase):
    def test_parses_pairs_and_skips_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allow.txt"
            path.write_text(
                "# comment\n0x1000:0x1040  # known nested\n\n", encoding="utf-8"
            )
            self.assertEqual(
                read_overlap_allowlist(path), {(0x1000, 0x1040)}
            )

    def test_missing_file_is_empty(self) -> None:
        self.assertEqual(read_overlap_allowlist(Path("/nonexistent")), set())


if __name__ == "__main__":
    unittest.main()
