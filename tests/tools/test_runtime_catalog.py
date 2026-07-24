#!/usr/bin/env python3
"""Contracts for the modular semantic runtime-test catalog and protocol."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.runtime.catalog import TESTS, find_test, missing_required_oracles, tests_in_suite
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
                "easy_turns_advance",
                "map_zoom_toggle_remains_responsive",
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
        config_pattern = re.compile(
            r'RuntimeScenarioConfig\s+\w+\s*=\s*\{\s*"([a-z0-9_]+)"\s*,'
            r"\s*\w+\s*,\s*(true|false)\s*,",
            re.MULTILINE,
        )
        snapshot_capable = set()
        for source_path in (
            REPO_ROOT / "tests/runtime/native/scenarios"
        ).glob("*Test.cpp"):
            source = source_path.read_text(encoding="utf-8")
            for name, random_game in config_pattern.findall(source):
                if random_game == "true":
                    snapshot_capable.add(name)

        ui_required = {test.name for test in TESTS if "ui" in test.required_oracles}
        self.assertLessEqual(ui_required, snapshot_capable)


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


if __name__ == "__main__":
    unittest.main()
