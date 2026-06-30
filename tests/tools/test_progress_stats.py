#!/usr/bin/env python3
"""Tests for tools.reccmp.progress_stats."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.reccmp.progress_stats import (
    format_delta,
    format_value,
    function_changes,
    metric_changes,
    parse_noise_counts,
    parse_optional_int,
    parse_report_counts,
    pct,
)


class PctTests(unittest.TestCase):
    def test_normal_ratio(self) -> None:
        self.assertAlmostEqual(pct(50, 100), 50.0)

    def test_zero_denominator(self) -> None:
        self.assertEqual(pct(10, 0), 0.0)

    def test_full_coverage(self) -> None:
        self.assertAlmostEqual(pct(100, 100), 100.0)

    def test_zero_numerator(self) -> None:
        self.assertAlmostEqual(pct(0, 100), 0.0)

    def test_partial(self) -> None:
        self.assertAlmostEqual(pct(1, 3), 100.0 / 3)


class ParseOptionalIntTests(unittest.TestCase):
    def test_decimal(self) -> None:
        self.assertEqual(parse_optional_int("42"), 42)

    def test_hex(self) -> None:
        self.assertEqual(parse_optional_int("0x1A"), 0x1A)

    def test_hex_uppercase(self) -> None:
        self.assertEqual(parse_optional_int("0XFF"), 0xFF)

    def test_empty_returns_none(self) -> None:
        self.assertIsNone(parse_optional_int(""))

    def test_whitespace_returns_none(self) -> None:
        self.assertIsNone(parse_optional_int("   "))

    def test_whitespace_stripped(self) -> None:
        self.assertEqual(parse_optional_int("  42  "), 42)


class FormatValueTests(unittest.TestCase):
    def test_pct_format(self) -> None:
        self.assertEqual(format_value(50.123, "pct"), "50.12%")

    def test_int_format(self) -> None:
        self.assertEqual(format_value(42, "int"), "42")

    def test_pct_zero(self) -> None:
        self.assertEqual(format_value(0.0, "pct"), "0.00%")


class FormatDeltaTests(unittest.TestCase):
    def test_positive_pct_delta(self) -> None:
        self.assertEqual(format_delta(50.5, 50.0, "pct"), "+0.50 pp")

    def test_negative_pct_delta(self) -> None:
        self.assertEqual(format_delta(49.0, 50.0, "pct"), "-1.00 pp")

    def test_positive_int_delta(self) -> None:
        self.assertEqual(format_delta(15, 10, "int"), "+5")

    def test_negative_int_delta(self) -> None:
        self.assertEqual(format_delta(8, 10, "int"), "-2")

    def test_zero_delta(self) -> None:
        self.assertEqual(format_delta(10, 10, "int"), "+0")


class FunctionChangesTests(unittest.TestCase):
    def test_detects_regression(self) -> None:
        base = {"0x100": {"m": 0.95, "n": "Foo"}}
        curr = {"0x100": {"m": 0.80, "n": "Foo"}}
        regressed, unpaired_now, improved, newly_paired = function_changes(curr, base)
        self.assertEqual(len(regressed), 1)
        self.assertEqual(regressed[0][0], "0x100")
        self.assertEqual(improved, 0)
        self.assertEqual(newly_paired, 0)

    def test_detects_improvement(self) -> None:
        base = {"0x100": {"m": 0.80, "n": "Foo"}}
        curr = {"0x100": {"m": 0.95, "n": "Foo"}}
        regressed, unpaired_now, improved, newly_paired = function_changes(curr, base)
        self.assertEqual(len(regressed), 0)
        self.assertEqual(improved, 1)

    def test_detects_newly_paired(self) -> None:
        base = {}
        curr = {"0x100": {"m": 0.90, "n": "Foo"}}
        regressed, unpaired_now, improved, newly_paired = function_changes(curr, base)
        self.assertEqual(newly_paired, 1)
        self.assertEqual(len(regressed), 0)

    def test_detects_unpaired(self) -> None:
        base = {"0x100": {"m": 0.90, "n": "Foo"}}
        curr = {}
        regressed, unpaired_now, improved, newly_paired = function_changes(curr, base)
        self.assertEqual(len(unpaired_now), 1)
        self.assertEqual(unpaired_now[0][0], "0x100")

    def test_no_change_within_epsilon(self) -> None:
        base = {"0x100": {"m": 0.90, "n": "Foo"}}
        curr = {"0x100": {"m": 0.90 + 1e-6, "n": "Foo"}}
        regressed, unpaired_now, improved, newly_paired = function_changes(curr, base)
        self.assertEqual(len(regressed), 0)
        self.assertEqual(improved, 0)

    def test_regression_sorted_by_biggest_drop(self) -> None:
        base = {
            "0x100": {"m": 0.90, "n": "A"},
            "0x200": {"m": 0.95, "n": "B"},
        }
        curr = {
            "0x100": {"m": 0.85, "n": "A"},
            "0x200": {"m": 0.70, "n": "B"},
        }
        regressed, _, _, _ = function_changes(curr, base)
        self.assertEqual(len(regressed), 2)
        self.assertEqual(regressed[0][0], "0x200")


class ParseReportCountsTests(unittest.TestCase):
    def test_parses_report_json(self) -> None:
        report = {
            "data": [
                {"address": "0x100", "matching": 1.0, "name": "Foo"},
                {"address": "0x200", "matching": 0.85, "name": "Bar"},
                {"address": "0x300", "matching": 1.0, "name": "Baz"},
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(report, f)
            path = Path(f.name)

        result = parse_report_counts(path)
        self.assertEqual(result["compared_fun_count"], 3)
        self.assertEqual(result["aligned_fun_count"], 2)
        self.assertEqual(result["not_aligned_compared_count"], 1)
        self.assertAlmostEqual(result["avg_matching_pct"], (1.0 + 0.85 + 1.0) / 3 * 100.0)
        path.unlink()

    def test_empty_report(self) -> None:
        report = {"data": []}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(report, f)
            path = Path(f.name)

        result = parse_report_counts(path)
        self.assertEqual(result["compared_fun_count"], 0)
        self.assertEqual(result["aligned_fun_count"], 0)
        self.assertAlmostEqual(result["avg_matching_pct"], 0.0)
        path.unlink()


class ParseNoiseCountsTests(unittest.TestCase):
    def test_counts_noise_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write("Dropped duplicate address 0x100\n")
            f.write("Dropped duplicate address 0x200\n")
            f.write("Failed to match function at 0x300\n")
            f.write("Invalid address 0x400\n")
            f.write("Normal output line\n")
            path = Path(f.name)

        result = parse_noise_counts(path)
        self.assertEqual(result["dropped_duplicate_address_count"], 2)
        self.assertEqual(result["failed_to_match_function_count"], 1)
        self.assertEqual(result["invalid_address_count"], 1)
        path.unlink()

    def test_missing_file_returns_zeros(self) -> None:
        result = parse_noise_counts(Path("/nonexistent/file.log"))
        self.assertEqual(result["dropped_duplicate_address_count"], 0)
        self.assertEqual(result["failed_to_match_function_count"], 0)
        self.assertEqual(result["invalid_address_count"], 0)


class MetricChangesTests(unittest.TestCase):
    def test_no_baseline_returns_empty(self) -> None:
        improved, worsened, changed = metric_changes({"aligned_fun_count": 10}, None)
        self.assertEqual(improved, [])
        self.assertEqual(worsened, [])
        self.assertEqual(changed, [])

    def test_improvement_detected(self) -> None:
        entry = {"aligned_fun_count": 15}
        baseline = {"aligned_fun_count": 10}
        improved, worsened, _ = metric_changes(entry, baseline)
        self.assertEqual(len(improved), 1)
        self.assertEqual(len(worsened), 0)
        self.assertIn("aligned functions (100%)", improved[0])

    def test_worsened_detected(self) -> None:
        entry = {"aligned_fun_count": 5}
        baseline = {"aligned_fun_count": 10}
        improved, worsened, _ = metric_changes(entry, baseline)
        self.assertEqual(len(improved), 0)
        self.assertEqual(len(worsened), 1)

    def test_no_change_not_reported(self) -> None:
        entry = {"aligned_fun_count": 10}
        baseline = {"aligned_fun_count": 10}
        improved, worsened, changed = metric_changes(entry, baseline)
        self.assertEqual(improved, [])
        self.assertEqual(worsened, [])
        self.assertEqual(changed, [])


if __name__ == "__main__":
    unittest.main()
