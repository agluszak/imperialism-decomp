#!/usr/bin/env python3
"""Tests for compact committed per-function reccmp baselines."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.common.function_baseline import (
    load_function_baseline,
    write_function_baseline_atomic,
)


class FunctionBaselineTests(unittest.TestCase):
    def test_round_trip_is_sorted_and_preserves_names(self) -> None:
        functions = {
            "0x500000": {"m": 0.125, "n": "Name, with comma"},
            "0x400000": {"m": 1.0, "n": "Exact::Method"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "functions.csv"
            write_function_baseline_atomic(path, functions)

            self.assertEqual(
                path.read_text(encoding="utf-8").splitlines()[1].split("|", 1)[0],
                "0x400000",
            )
            self.assertEqual(load_function_baseline(path), functions)

    def test_missing_baseline_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(load_function_baseline(Path(directory) / "missing.csv"))

    def test_rejects_unexpected_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "functions.csv"
            path.write_text("address|matching\n0x400000|1.0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unexpected function baseline columns"):
                load_function_baseline(path)


if __name__ == "__main__":
    unittest.main()
