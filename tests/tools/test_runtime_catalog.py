#!/usr/bin/env python3
"""Contracts for the modular semantic runtime-test catalog and protocol."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.runtime.catalog import (
    TESTS,
    find_test,
    missing_required_oracles,
    record_missing_oracles,
    tests_in_suite,
)
from tools.runtime.protocol import validate_result


REPO_ROOT = Path(__file__).resolve().parents[2]


class RuntimeCatalogTests(unittest.TestCase):
    def test_names_are_unique(self) -> None:
        names = [test.name for test in TESTS]
        self.assertEqual(len(names), len(set(names)))

    def test_pr_suite_is_nonempty_and_part_of_full(self) -> None:
        pr_names = {test.name for test in tests_in_suite("pr")}
        full_names = {test.name for test in tests_in_suite("full")}
        self.assertTrue(pr_names)
        self.assertLessEqual(pr_names, full_names)

    def test_known_broken_reproducers_are_not_in_full_suite(self) -> None:
        repro_names = {test.name for test in tests_in_suite("repro")}
        full_names = {test.name for test in tests_in_suite("full")}
        self.assertEqual(
            repro_names,
            {
                "city_screen_opens",
                "diplomacy_screen_operates",
                "easy_turns_advance",
                "map_zoom_toggle_remains_responsive",
                "trade_screen_operates",
            },
        )
        self.assertFalse(repro_names & full_names)

    def test_native_registry_matches_host_catalog(self) -> None:
        source = (
            REPO_ROOT / "tests/runtime/native/RuntimeRegistry.cpp"
        ).read_text(encoding="utf-8")
        native_names = set(re.findall(r'^\s*\{"([a-z0-9_]+)",', source, re.MULTILINE))
        self.assertEqual(native_names, {test.name for test in TESTS})

    def test_find_test_rejects_unknown_name(self) -> None:
        self.assertIsNone(find_test("not_a_runtime_test"))

    def test_required_oracle_cannot_be_silently_skipped(self) -> None:
        test = find_test("random_game_easy_skips_capital")
        self.assertIsNotNone(test)
        self.assertEqual(
            missing_required_oracles(test, {"ui_oracle": {"status": "passed"}}),
            ("map",),
        )

    def test_ui_oracle_requirements_have_native_snapshot_policy(self) -> None:
        snapshot_capable = set()
        for source_path in (
            REPO_ROOT / "tests/runtime/native/scenarios"
        ).glob("*Test.cpp"):
            source = source_path.read_text(encoding="utf-8")
            name = re.search(r'return "([a-z0-9_]+)";', source)
            random_flow = re.search(
                r"bool UsesRandomGameFlow\(\) const override\s*\{\s*return true;\s*\}",
                source,
            )
            if name is not None and random_flow is not None:
                snapshot_capable.add(name.group(1))

        ui_required = {test.name for test in TESTS if "ui" in test.required_oracles}
        self.assertLessEqual(ui_required, snapshot_capable)

    def test_native_scenarios_own_behavior_in_concrete_classes(self) -> None:
        header = (
            REPO_ROOT / "tests/runtime/native/scenarios/RuntimeScenario.h"
        ).read_text(encoding="utf-8")
        self.assertNotIn("RuntimeScenarioConfig", header)
        self.assertNotIn("RuntimeScenarioCompletion", header)

        for source_path in (
            REPO_ROOT / "tests/runtime/native/scenarios"
        ).glob("*Test.cpp"):
            source = source_path.read_text(encoding="utf-8")
            self.assertRegex(source, r"class \w+TestCase : public RuntimeScenario")


class RuntimeProtocolTests(unittest.TestCase):
    def test_valid_result(self) -> None:
        validate_result(
            {"format_version": 1, "name": "boot_managers", "seed": 1, "status": "passed"},
            "boot_managers",
            1,
        )

    def test_wrong_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "format_version"):
            validate_result(
                {"format_version": 2, "name": "boot_managers", "seed": 1, "status": "passed"},
                "boot_managers",
                1,
            )

    def test_wrong_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "requested"):
            validate_result(
                {"format_version": 1, "name": "other", "seed": 1, "status": "passed"},
                "boot_managers",
                1,
            )


class MissingOracleRecordingTests(unittest.TestCase):
    """A missing oracle must never displace the failure that caused it.

    The driver snapshots map state only on a passing finish, so any crash or phase
    timeout in a map-oracle test leaves the oracle absent.  Reporting that absence as
    the failure hid every real cause behind "missing required oracle(s): map".
    """

    def test_no_missing_oracles_leaves_the_result_untouched(self) -> None:
        result = {"status": "passed"}
        record_missing_oracles(result, ())
        self.assertEqual(result, {"status": "passed"})

    def test_passing_run_is_failed_by_a_missing_oracle(self) -> None:
        result = {"status": "passed"}
        record_missing_oracles(result, ("map",))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"], "missing required oracle(s): map")
        self.assertEqual(result["missing_oracles"], ["map"])
        self.assertNotIn("secondary_failures", result)

    def test_primary_failure_survives_a_missing_oracle(self) -> None:
        result = {"status": "failed", "failure": "phase timeout in waiting_for_strategic_map"}
        record_missing_oracles(result, ("map",))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"], "phase timeout in waiting_for_strategic_map")
        self.assertEqual(result["secondary_failures"], ["missing required oracle(s): map"])
        self.assertEqual(result["missing_oracles"], ["map"])

    def test_failed_run_without_a_message_uses_the_host_classification(self) -> None:
        result = {"status": "failed"}
        record_missing_oracles(result, ("map", "ui"), fallback_failure="access violation")
        self.assertEqual(result["failure"], "access violation")
        self.assertEqual(result["secondary_failures"], ["missing required oracle(s): map, ui"])

    def test_secondary_failures_accumulate(self) -> None:
        result = {"status": "failed", "failure": "crash", "secondary_failures": ["earlier note"]}
        record_missing_oracles(result, ("map",))
        self.assertEqual(
            result["secondary_failures"], ["earlier note", "missing required oracle(s): map"]
        )

    def test_absent_map_oracle_report_still_counts_as_missing(self) -> None:
        spec = find_test("random_game_enters_map")
        assert spec is not None
        self.assertEqual(missing_required_oracles(spec, {"status": "failed"}), ("ui", "map"))

    def test_skipped_map_oracle_report_counts_as_missing(self) -> None:
        spec = find_test("save_load_roundtrip")
        assert spec is not None
        result = {"status": "failed", "map_oracle": {"status": "skipped", "reason": "no map_state"}}
        self.assertEqual(missing_required_oracles(spec, result), ("map",))


if __name__ == "__main__":
    unittest.main()
