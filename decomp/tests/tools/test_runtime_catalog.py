#!/usr/bin/env python3
"""Contracts for the modular semantic runtime-test catalog and protocol."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.runtime.catalog import (
    TESTS,
    ExpectedFailureSpec,
    RuntimeTestSpec,
    apply_expected_failure,
    find_test,
    missing_required_oracles,
    record_missing_oracles,
    tests_in_suite,
)
from tools.runtime.generate_native_registry import render_factories, render_registry
from tools.runtime.fixtures import validate_fixture_metadata
from tools.runtime.protocol import validate_published_result, validate_result


REPO_ROOT = Path(__file__).resolve().parents[2]


class RuntimeCatalogTests(unittest.TestCase):
    def test_names_are_unique(self) -> None:
        names = [test.name for test in TESTS]
        self.assertEqual(len(names), len(set(names)))

    def test_native_factories_are_unique(self) -> None:
        factories = [test.native_factory for test in TESTS]
        self.assertEqual(len(factories), len(set(factories)))

    def test_native_transition_oracle_is_the_sole_model_differential_entry(self) -> None:
        oracle = find_test("native_transition_oracle")
        loaded_turn = find_test("easy_turn_from_save")
        self.assertIsNotNone(oracle)
        self.assertIsNotNone(loaded_turn)
        assert oracle is not None
        assert loaded_turn is not None
        self.assertEqual(oracle.fixture, loaded_turn.fixture)
        self.assertEqual(oracle.evidence_kind, "retail_fixture_oracle")
        self.assertEqual(oracle.native_snapshots, ("game_state",))
        self.assertEqual(oracle.suites, ())
        self.assertEqual(oracle.required_oracles, ())
        self.assertIn("NativeTransitionOracle()", render_factories())
        self.assertIn('"native_transition_oracle"', render_registry())
        self.assertIsNone(find_test("rolling_stock"))
        self.assertIsNone(find_test("city_item_order_increase"))
        self.assertIsNone(find_test("first_turn_alert_phase"))
        self.assertIsNone(find_test("first_turn_trade_phase"))
        self.assertIsNone(find_test("nation_resource_yield_rebuild"))
    def test_pr_suite_is_nonempty_and_part_of_full(self) -> None:
        pr_names = {test.name for test in tests_in_suite("pr")}
        full_names = {test.name for test in tests_in_suite("full")}
        self.assertTrue(pr_names)
        self.assertLessEqual(pr_names, full_names)

    def test_expected_failures_are_isolated_from_gating_suites(self) -> None:
        full_names = {test.name for test in tests_in_suite("full")}
        for test in TESTS:
            if test.expected_failure is None:
                continue
            self.assertIn("repro", test.suites)
            self.assertNotIn(test.name, full_names)

    def test_catalog_fixtures_have_valid_retail_provenance_sidecars(self) -> None:
        fixture_root = REPO_ROOT.parent / "fixtures" / "retail"
        for test in TESTS:
            if test.fixture is None:
                continue
            metadata = validate_fixture_metadata(fixture_root / test.fixture.filename)
            self.assertEqual(metadata["source_kind"], test.fixture.evidence_kind)

    def test_expected_failure_distinguishes_match_difference_and_xpass(self) -> None:
        spec = RuntimeTestSpec(
            "known_failure",
            "KnownFailureTest",
            ("repro",),
            "internal_invariant",
            expected_failure=ExpectedFailureSpec(
                phases=("waiting_for_map",), classifications=("crash",)
            ),
        )
        matched = {
            "status": "failed",
            "summary": {"phase": "waiting_for_map", "classification": "crash"},
        }
        apply_expected_failure(spec, matched)
        self.assertEqual(matched["status"], "expected_failure")

        different = {
            "status": "failed",
            "summary": {"phase": "different_phase", "classification": "crash"},
        }
        apply_expected_failure(spec, different)
        self.assertEqual(different["status"], "failed")

        passed = {"status": "passed"}
        apply_expected_failure(spec, passed)
        self.assertEqual(passed["status"], "failed")
        self.assertEqual(passed["expectation_outcome"], "unexpected_pass")


class RuntimeProtocolTests(unittest.TestCase):
    @staticmethod
    def result(
        name: str = "boot_managers", seed: int = 1, **overrides: object
    ) -> dict:
        return {
            "name": name,
            "seed": seed,
            "status": "passed",
            "captures": {},
            **overrides,
        }

    def test_valid_result_is_accepted(self) -> None:
        validate_result(self.result(), "boot_managers", 1)

    def test_published_result_requires_catalog_evidence_kind(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence_kind"):
            validate_published_result(self.result(), "boot_managers", 1)
        validate_published_result(
            self.result(evidence_kind="internal_invariant"), "boot_managers", 1
        )
        with self.assertRaisesRegex(ValueError, "evidence_kind"):
            validate_published_result(
                self.result(evidence_kind="not_a_real_kind"), "boot_managers", 1
            )

    def test_published_result_allows_expected_failure_status(self) -> None:
        validate_published_result(
            self.result(status="expected_failure", evidence_kind="internal_invariant"),
            "boot_managers",
            1,
        )

    def test_extra_top_level_fields_are_allowed(self) -> None:
        validate_result(
            self.result(evidence_kind="host-side metadata only"), "boot_managers", 1
        )

    def test_wrong_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "requested"):
            validate_result(self.result(name="turn_event_queue_bounds"), "boot_managers", 1)

    def test_wrong_seed_or_status_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "seed"):
            validate_result(self.result(seed=2), "boot_managers", 1)
        with self.assertRaisesRegex(ValueError, "status"):
            validate_result(self.result(status="expected_failure"), "boot_managers", 1)

    def test_captures_must_be_an_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "captures"):
            validate_result(self.result(captures=[]), "boot_managers", 1)

    def test_capture_payloads_are_not_validated_by_python(self) -> None:
        captures = {
            "game_state": {"new_rust_field": ["owned", {"semantic": True}]},
            "coarse_map_generation": {"unmodeled": "payload"},
            "random_map_terrain": {"unmodeled": "payload"},
            "random_game_setup": {"unmodeled": "payload"},
            "map_state": {"unmodeled": "payload"},
            "serialization_roundtrip": {"unmodeled": "payload"},
            "ui_tree": {
                "snapshots": [],
                "current": None,
                "capital_confirmation": None,
            },
        }
        validate_result(self.result(captures=captures), "boot_managers", 1)

    def test_native_registry_knows_the_random_setup_capture(self) -> None:
        self.assertIn("kRuntimeCaptureRandomGameSetup", render_registry())

    def test_missing_required_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_result(
                {"name": "boot_managers", "seed": 1, "status": "passed"},
                "boot_managers",
                1,
            )


class MissingOracleRecordingTests(unittest.TestCase):
    def test_primary_failure_survives_a_missing_oracle(self) -> None:
        result = {"status": "failed", "failure": "phase timeout in waiting_for_strategic_map"}
        record_missing_oracles(result, ("map",))
        self.assertEqual(result["failure"], "phase timeout in waiting_for_strategic_map")
        self.assertEqual(result["secondary_failures"], ["missing required oracle(s): map"])

    def test_absent_map_oracle_report_still_counts_as_missing(self) -> None:
        spec = find_test("random_game_enters_map")
        assert spec is not None
        self.assertEqual(missing_required_oracles(spec, {"status": "failed"}), ("ui", "map"))


if __name__ == "__main__":
    unittest.main()
