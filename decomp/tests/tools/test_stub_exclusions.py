"""Tests for stub exclusions, which carry no alias or type identity."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.common.stub_exclusions import load_stub_exclusions


class TestStubExclusions(unittest.TestCase):
    def load(self, content: str) -> tuple[set[int], list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exclusions.csv"
            path.write_text(content)
            return load_stub_exclusions(path)

    def test_addresses_have_no_canonical_or_type_metadata(self) -> None:
        addresses, errors = self.load("original_address\n0x00426ec0\n004849c0\n")
        self.assertEqual(addresses, {0x426EC0, 0x4849C0})
        self.assertEqual(errors, [])

    def test_alias_schema_rejected(self) -> None:
        addresses, errors = self.load(
            "original_address|canonical_address\n0x1000|0x2000\n"
        )
        self.assertEqual(addresses, set())
        self.assertEqual(len(errors), 1)

    def test_duplicate_invalid_and_extra_fields_rejected(self) -> None:
        addresses, errors = self.load(
            "original_address\n0x1000\n0x1000\nunknown\n0x2000|0x3000\n"
        )
        self.assertEqual(addresses, {0x1000})
        self.assertEqual(len(errors), 3)

    def test_missing_file_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                load_stub_exclusions(Path(directory) / "missing.csv"), (set(), [])
            )


if __name__ == "__main__":
    unittest.main()
