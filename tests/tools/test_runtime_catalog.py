#!/usr/bin/env python3
"""Contracts for the modular semantic runtime-test catalog and protocol."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from pathlib import Path

from tools.runtime.catalog import (
    TESTS,
    ExpectedFailureSpec,
    RuntimeTestSpec,
    apply_expected_failure,
    find_test,
    missing_required_oracles,
    promotion_candidates,
    record_missing_oracles,
    tests_in_suite,
)
from tools.runtime.fixtures import validate_fixture_metadata
from tools.runtime.generate_native_registry import render_registry
from tools.runtime.protocol import (
    GENERATED_WORLD_BORDER_LINK_FIELDS,
    GENERATED_WORLD_TILE_FIELDS,
    validate_game_snapshot,
    validate_generated_world,
    validate_result,
)


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

    def test_expected_failures_are_isolated_from_gating_suites(self) -> None:
        full_names = {test.name for test in tests_in_suite("full")}
        for test in TESTS:
            if test.expected_failure is None:
                continue
            self.assertIn("repro", test.suites)
            self.assertNotIn(test.name, full_names)

    def test_native_factories_are_unique(self) -> None:
        factories = [test.native_factory for test in TESTS]
        self.assertEqual(len(factories), len(set(factories)))

    def test_generated_registry_contains_each_catalog_entry_once(self) -> None:
        generated = render_registry()
        for test in TESTS:
            row = f'{{"{test.name}", {test.native_factory}(),'
            self.assertEqual(generated.count(row), test.execution == "game")
        self.assertEqual(generated.count("RuntimeTestDescriptor g_descriptors[]"), 1)

    def test_expected_failures_require_a_structured_signature(self) -> None:
        for test in tests_in_suite("repro"):
            expected = test.expected_failure
            self.assertIsNotNone(expected)
            assert expected is not None
            self.assertTrue(
                expected.assertion_ids or expected.phases or expected.classifications
            )

    def test_expected_failure_distinguishes_match_difference_and_xpass(self) -> None:
        spec = RuntimeTestSpec(
            "known_failure",
            "KnownFailureTest",
            ("repro",),
            "internal_invariant",
            expected_failure=ExpectedFailureSpec(
                assertion_ids=("map.zoom",), classifications=("crash",)
            ),
        )
        matched = {
            "status": "failed",
            "assertion_id": "map.zoom",
            "classification": "crash",
        }
        apply_expected_failure(spec, matched)
        self.assertEqual(matched["status"], "expected_failure")
        self.assertEqual(matched["expectation_outcome"], "expected_failure")

        different = {
            "status": "failed",
            "assertion_id": "map.coast",
            "classification": "crash",
        }
        apply_expected_failure(spec, different)
        self.assertEqual(different["status"], "failed")
        self.assertEqual(different["expectation_outcome"], "different_failure")

        passed = {"status": "passed"}
        apply_expected_failure(spec, passed)
        self.assertEqual(passed["status"], "failed")
        self.assertEqual(passed["expectation_outcome"], "unexpected_pass")
        self.assertIn("XPASS", passed["failure"])

    def test_promotion_candidates_follow_catalog_order(self) -> None:
        later = RuntimeTestSpec(
            "later",
            "LaterTest",
            ("repro",),
            "internal_invariant",
            promotion_suites=("full",),
            promotion_order=2,
        )
        first = RuntimeTestSpec(
            "first",
            "FirstTest",
            ("repro",),
            "internal_invariant",
            promotion_suites=("full",),
            promotion_order=1,
        )
        results = {
            "later": {"expectation_outcome": "unexpected_pass"},
            "first": {"expectation_outcome": "unexpected_pass"},
        }
        with patch("tools.runtime.catalog.TESTS", (later, first)):
            candidates = promotion_candidates(results)
        orders = [test.promotion_order for test in candidates]
        self.assertEqual(orders, [1, 2])
        self.assertTrue(all(test.promotion_suites for test in candidates))

    def test_find_test_rejects_unknown_name(self) -> None:
        self.assertIsNone(find_test("not_a_runtime_test"))

    def test_catalog_fixtures_have_valid_retail_provenance_sidecars(self) -> None:
        fixture_root = REPO_ROOT / "tests/runtime/fixtures"
        for test in TESTS:
            if test.fixture is None:
                continue
            metadata = validate_fixture_metadata(
                fixture_root / test.fixture.filename, test.name
            )
            self.assertEqual(metadata["source_kind"], test.fixture.evidence_kind)

    def test_required_oracle_cannot_be_silently_skipped(self) -> None:
        test = find_test("random_game_easy_skips_capital")
        self.assertIsNotNone(test)
        self.assertEqual(
            missing_required_oracles(test, {"ui_oracle": {"status": "passed"}}),
            ("map",),
        )

    def test_oracle_requirements_have_declared_native_snapshot_policy(self) -> None:
        for test in TESTS:
            self.assertLessEqual(set(test.required_oracles), set(test.native_snapshots))

    def test_native_scenarios_do_not_use_legacy_configuration_objects(self) -> None:
        header = (
            REPO_ROOT / "tests/runtime/native/scenarios/RuntimeScenario.h"
        ).read_text(encoding="utf-8")
        self.assertNotIn("RuntimeScenarioConfig", header)
        self.assertNotIn("RuntimeScenarioCompletion", header)


class RuntimeProtocolTests(unittest.TestCase):
    @staticmethod
    def game_snapshot() -> dict:
        return {
            "schema": "imperialism.game_snapshot.v1",
            "sections": [
                "metadata",
                "rng",
                "world",
                "nations",
                "economy",
                "military",
                "missions",
                "pending",
            ],
            "hashes": {
                "metadata": "0123abcd",
                "rng": "0123abcd",
                "world": "0123abcd",
                "nations": "0123abcd",
                "economy": "0123abcd",
                "military": "0123abcd",
                "missions": "0123abcd",
                "pending": "0123abcd",
                "state": "0123abcd",
            },
            "metadata": {},
            "rng": {},
            "world": {"width": 108, "height": 60, "wrap": 0, "tiles": [[0] * 10] * 6480},
            "nations": {
                "records": [
                    {
                        "slot": slot,
                        "kind": "major" if slot < 7 else "minor",
                        "present": False,
                    }
                    for slot in range(23)
                ]
            },
            "economy": {
                "cities": [
                    {"nation": slot, "present": False} for slot in range(7)
                ]
            },
            "military": {"units": [], "ships": [], "task_forces": []},
            "missions": {"records": []},
            "pending": {
                "turn_flow_status_flags": 0,
                "nations": [
                    {
                        "nation": nation,
                        "turn_events": [],
                        "proposals": [],
                        "turn_summary": [],
                        "turn_start_events": [],
                    }
                    for nation in range(7)
                ],
                "war_transitions": [],
            },
        }

    @staticmethod
    def generated_world_snapshot() -> dict:
        province = {
            "index": 0,
            "owner_nation": -1,
            "former_owner_nation": -1,
            "development_stage": 0,
            "fort_level": 0,
            "city_tile": -1,
            "last_turn_tick": 999,
            "adjacent_region_count": 0,
            "adjacent_region_ids": [-1] * 12,
            "adjacent_region_anchor_tiles": [-1] * 12,
            "linked_region_count": 0,
            "secondary_neighbor_tile": -1,
            "primary_neighbor_tile": -1,
            "linked_tile_indices": [-1] * 32,
            "resource_development_counts": [0] * 10,
            "city_score": 0,
            "navy_order_reachable": 0,
            "explored_by_nation_mask": 0,
            "resource_presence_mask": 0,
            "region_class": -1,
            "city_name": "",
        }
        provinces = []
        for index in range(384):
            record = dict(province)
            record["index"] = index
            provinces.append(record)
        return {
            "schema": "imperialism.generated_world.v1",
            "tile_fields": list(GENERATED_WORLD_TILE_FIELDS),
            "border_link_fields": list(GENERATED_WORLD_BORDER_LINK_FIELDS),
            "map": {
                "width": 108,
                "height": 60,
                "scenario_tag": "-1174031836",
                "retail_topology_byte": 0,
                "wraps_horizontally": True,
                "strategic_map_palette_preview_ready": 1,
                "map_manager_ready": 1,
                "map_data_ready": 1,
                "tile_search_flag": 0,
                "city_score_total": 0,
                "pending_river_mouth_tile": -1,
            },
            "rng": {
                "runtime_seed": 1,
                "crt_rand_state": 2745024,
                "map_generation_lcg": 1,
                "zone_status_lcg": 1,
            },
            "coarse_generation": {
                "initial_map_lcg": 1,
                "attempt_count": 1,
                "attempts": [
                    {
                        "index": 0,
                        "draw_count": 1,
                        "map_lcg_after_seeding": 2,
                        "pre_validation_grid": [-1] * 405,
                        "city_region_next_id": -1,
                        "city_region_ids": [-1] * 23,
                        "group_members": [-1] * 21,
                        "post_validation_grid": [-1] * 405,
                        "error_check_failed": 0,
                        "has_continuous_ocean_column": 1,
                        "frontier_mask_complete": 1,
                        "accepted": 1,
                        "map_lcg_after_validation": 2,
                    }
                ],
                "accepted_map_lcg": 2,
                "accepted_grid": [-1] * 405,
                "city_region_next_id": 22,
                "city_region_ids": list(range(23)),
                "group_members": [-1] * 21,
                "expanded_province_count": 0,
                "expanded_tile_fields": ["terrain_kind", "owner_nation", "province_index"],
                "expanded_tiles": [[0, -1, -1] for _ in range(6480)],
                "expanded_provinces": [],
            },
            "tiles": [[0] * len(GENERATED_WORLD_TILE_FIELDS) for _ in range(6480)],
            "provinces": provinces,
            "ocean_context_array_count": 1,
            "sea_region_count": 1,
            "sea_regions": [
                {
                    "index": 0,
                    "kind": "zone",
                    "context_ordinal": 0,
                    "status_code": 0,
                    "display_name": "",
                    "tile_or_terrain_id": -1,
                    "nation_key_mask": 0,
                    "seed_nation_id": 0,
                    "active_tile": -1,
                    "distance_level": 0,
                    "port_tile": -1,
                    "primary_neighbors": [],
                    "secondary_neighbors": [],
                }
            ],
            "route_count": 1,
            "routes": [[0, 0, 1, 1]],
            "border_links": [[0, 0, 1, 1, 0, 1, 0, 1, 0, 0]],
        }

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

    def test_game_snapshot_foundation_is_validated(self) -> None:
        validate_game_snapshot(self.game_snapshot())

    def test_game_snapshot_rejects_wrong_tile_count(self) -> None:
        snapshot = self.game_snapshot()
        snapshot["world"]["tiles"] = []
        with self.assertRaisesRegex(ValueError, "tile count"):
            validate_game_snapshot(snapshot)

    def test_game_snapshot_rejects_malformed_hash(self) -> None:
        snapshot = self.game_snapshot()
        snapshot["hashes"]["world"] = "not-a-hash"
        with self.assertRaisesRegex(ValueError, "hash for world"):
            validate_game_snapshot(snapshot)

    def test_game_snapshot_rejects_wrong_nation_count(self) -> None:
        snapshot = self.game_snapshot()
        snapshot["nations"]["records"] = []
        with self.assertRaisesRegex(ValueError, "23 records"):
            validate_game_snapshot(snapshot)

    def test_game_snapshot_requires_the_special_resource_trade_balance(self) -> None:
        snapshot = self.game_snapshot()
        major = {
            field: [0] * 23
            for field in (
                "diplomacy_policy_by_nation",
                "diplomacy_grant_by_nation",
                "need_current_by_type",
                "need_target_by_type",
                "relation_delta_current",
                "purchased_items_by_resource",
                "item_potentials",
                "unfilled_trade_turns_by_resource",
                "transported_items_by_resource",
                "remembered_trade_offers_by_resource",
                "candidate_nation_flags",
                "colony_boycott_flags",
            )
        }
        major.update(
            capacities=[0] * 4,
            aid_allocation_matrix=[0] * 0x170,
            pending_action_status=[0] * 13,
            pending_action_payload_by_action=[0] * 13,
        )
        snapshot["nations"]["records"][0] = {
            "slot": 0,
            "kind": "major",
            "present": True,
            "need_level_by_nation": [0] * 23,
            "major": major,
        }
        with self.assertRaisesRegex(ValueError, "special-resource trade balance"):
            validate_game_snapshot(snapshot)

    def test_game_snapshot_rejects_wrong_city_count(self) -> None:
        snapshot = self.game_snapshot()
        snapshot["economy"]["cities"] = []
        with self.assertRaisesRegex(ValueError, "seven city records"):
            validate_game_snapshot(snapshot)

    def test_generated_world_v1_is_validated(self) -> None:
        validate_generated_world(self.generated_world_snapshot())

    def test_result_validates_generated_world(self) -> None:
        result = {
            "format_version": 1,
            "name": "generated_world_snapshot",
            "seed": 1,
            "status": "passed",
            "generated_world": self.generated_world_snapshot(),
        }
        validate_result(result, "generated_world_snapshot", 1)

    def test_generated_world_rejects_wrong_tile_schema(self) -> None:
        snapshot = self.generated_world_snapshot()
        snapshot["tile_fields"][-1] = "pointer"
        with self.assertRaisesRegex(ValueError, "tile_fields"):
            validate_generated_world(snapshot)

    def test_generated_world_rejects_pointer_fields(self) -> None:
        snapshot = self.generated_world_snapshot()
        snapshot["sea_regions"][0]["next_pointer"] = 0x1234
        with self.assertRaisesRegex(ValueError, "fields"):
            validate_generated_world(snapshot)

    def test_generated_world_enforces_retail_topology_semantics(self) -> None:
        snapshot = self.generated_world_snapshot()
        snapshot["map"]["wraps_horizontally"] = False
        with self.assertRaisesRegex(ValueError, "wrap semantics"):
            validate_generated_world(snapshot)

    def test_generated_world_rejects_malformed_province_array(self) -> None:
        snapshot = self.generated_world_snapshot()
        snapshot["provinces"][0]["linked_tile_indices"] = []
        with self.assertRaisesRegex(ValueError, "linked_tile_indices"):
            validate_generated_world(snapshot)

    def test_generated_world_requires_active_route_count(self) -> None:
        snapshot = self.generated_world_snapshot()
        snapshot["route_count"] = 2
        with self.assertRaisesRegex(ValueError, "route_count"):
            validate_generated_world(snapshot)


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


class MapExpectationConsistencyTests(unittest.TestCase):
    """The seed-1 random-game scenarios generate one map; their oracles must agree.

    random_game_enters_map's expectation drifted four tiles away from its two siblings
    and stayed wrong for a long time, because the scenario aborted before map capture
    and so never compared them (imperialism-decomp-vtzb).  A disagreement here means
    either a real generation change -- in which case every one of these files moves
    together -- or one stale recording.
    """

    SEED1_RANDOM_GAME_SCENARIOS = (
        "random_game_easy_skips_capital",
        "random_game_introductory_exits_newspaper",
        "random_game_enters_map",
    )

    def _expectation(self, name: str) -> dict:
        path = REPO_ROOT / "tests" / "runtime" / "expectations" / f"{name}.seed1.json"
        self.assertTrue(path.is_file(), f"missing map expectation {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_seed1_random_games_expect_one_map(self) -> None:
        expectations = {
            name: self._expectation(name) for name in self.SEED1_RANDOM_GAME_SCENARIOS
        }
        for key in ("representative_tile", "owned_tiles", "terrain_counts", "wrap"):
            values = {name: value[key] for name, value in expectations.items()}
            distinct = {json.dumps(value, sort_keys=True) for value in values.values()}
            self.assertEqual(
                len(distinct),
                1,
                f"seed-1 random-game scenarios disagree on {key}: {values}",
            )

    def test_every_gating_map_oracle_test_has_a_seed1_expectation(self) -> None:
        for test in TESTS:
            if "map" not in test.required_oracles or test.fixture is not None:
                continue
            # repro-only entries are known-broken reproducers, not gates; they are
            # expected to have no recorded expectation yet.
            if set(test.suites) <= {"repro"}:
                continue
            path = REPO_ROOT / "tests" / "runtime" / "expectations" / f"{test.name}.seed1.json"
            self.assertTrue(path.is_file(), f"{test.name} requires the map oracle but has no {path}")


if __name__ == "__main__":
    unittest.main()


class ScenarioPolicyInCatalogTests(unittest.TestCase):
    """Harness policy belongs beside suites and evidence, not in a scenario's class body.

    Every scenario used to answer RecordsGameFlow()/RequiresScenarioUiSnapshot()/
    ObserveScenarioUiTree() with a hand-written override, which is why "a test overrides Script()
    only" was not true.
    """

    def test_snapshot_events_are_cpp_constants(self):
        """Names, not numbers: game/turn_event_codes.h stays the single source of the values."""
        for test in TESTS:
            for event in test.ui_snapshot_events:
                with self.subTest(test=test.name, event=event):
                    self.assertTrue(event.startswith("kTurnEvent"), event)

    def test_snapshot_events_imply_a_ui_snapshot(self):
        """Capturing a tree without declaring the ui snapshot would drop the evidence."""
        for test in TESTS:
            if test.ui_snapshot_events:
                with self.subTest(test=test.name):
                    self.assertIn("ui", test.native_snapshots)

    def test_no_scenario_overrides_the_policy_hooks(self):
        """The overrides are gone; a new one would silently outrank its catalog entry."""
        scenarios = (REPO_ROOT / "tests" / "runtime" / "native" / "scenarios").glob("*Test.cpp")
        offenders = []
        for path in scenarios:
            source = path.read_text(encoding="utf-8")
            for hook in ("RecordsGameFlow", "RequiresScenarioUiSnapshot", "ObserveScenarioUiTree"):
                if f"{hook}(" in source and "override" in source:
                    if any(f"{hook}(" in line and "override" in line for line in source.splitlines()):
                        offenders.append(f"{path.name}: {hook}")
        self.assertEqual([], offenders)

    def test_the_generated_descriptor_carries_the_policy(self):
        rendered = render_registry()
        self.assertIn("kCityScreenOpensSnapshotEvents[] = {kTurnEventCityProduction}", rendered)
        # boot_managers declares neither, so it must render the empty form.
        self.assertIn('{"boot_managers"', rendered)
        self.assertIn("false, 0, 0}", rendered)
