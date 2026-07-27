#!/usr/bin/env python3
"""Tests for the runtime-test runner's host-side failure classification."""

from __future__ import annotations

import unittest

import tempfile
from pathlib import Path

from tools.runtime.artifacts import prune_old_run_dirs
from tools.runtime.classification import classify_exit, classify_poll, no_progress_budget_seconds
from tools.runtime.oracles.map import compare_map_state


def heartbeat(elapsed_ms: int, last_progress_ms: int) -> dict:
    return {
        "phase": "waiting_for_strategic_map",
        "elapsed_ms": elapsed_ms,
        "last_progress_ms": last_progress_ms,
        "progress_counter": 4,
    }


class ClassifyPollTests(unittest.TestCase):
    def test_no_heartbeat_yet_is_not_classified(self) -> None:
        self.assertIsNone(classify_poll(None, None, 90.0))

    def test_young_process_without_heartbeat_is_healthy(self) -> None:
        self.assertIsNone(classify_poll(None, None, 90.0, process_age_seconds=5.0))

    def test_old_process_without_heartbeat_is_hung_boot(self) -> None:
        self.assertEqual(
            classify_poll(None, None, 90.0, process_age_seconds=60.1),
            "heartbeat_stopped",
        )

    def test_fresh_heartbeat_with_recent_progress_is_healthy(self) -> None:
        self.assertIsNone(classify_poll(heartbeat(30_000, 29_000), 0.5, 90.0))

    def test_stale_heartbeat_is_heartbeat_stopped(self) -> None:
        self.assertEqual(
            classify_poll(heartbeat(30_000, 29_000), 5.1, 90.0),
            "heartbeat_stopped",
        )

    def test_stale_check_precedes_no_progress_check(self) -> None:
        self.assertEqual(
            classify_poll(heartbeat(500_000, 0), 5.1, 90.0),
            "heartbeat_stopped",
        )

    def test_fresh_heartbeat_without_progress_is_pump_alive(self) -> None:
        self.assertEqual(
            classify_poll(heartbeat(200_000, 1_000), 0.5, 90.0),
            "pump_alive_no_semantic_progress",
        )

    def test_no_progress_budget_is_inclusive_at_the_boundary(self) -> None:
        self.assertIsNone(classify_poll(heartbeat(91_000, 1_000), 0.5, 90.0))

    def test_held_session_is_exempt_from_the_no_progress_check(self) -> None:
        held = dict(heartbeat(500_000, 0), hold=True)
        self.assertIsNone(classify_poll(held, 0.5, 90.0))

    def test_held_session_still_fails_on_stale_heartbeat(self) -> None:
        held = dict(heartbeat(500_000, 0), hold=True)
        self.assertEqual(classify_poll(held, 5.1, 90.0), "heartbeat_stopped")

    def test_malformed_heartbeat_fields_are_tolerated(self) -> None:
        self.assertIsNone(classify_poll({"phase": "boot"}, 0.5, 90.0))
        self.assertIsNone(
            classify_poll({"elapsed_ms": "junk", "last_progress_ms": 0}, 0.5, 90.0)
        )


class ClassifyExitTests(unittest.TestCase):
    def test_result_file_present_is_not_classified(self) -> None:
        self.assertIsNone(classify_exit(0, True))
        self.assertIsNone(classify_exit(5, True))

    def test_nonzero_exit_after_liveness_is_crash(self) -> None:
        self.assertEqual(classify_exit(-11, False, saw_heartbeat=True), "crash")

    def test_nonzero_exit_before_any_heartbeat_is_not_called_a_crash(self) -> None:
        """A process that never signalled liveness never reached the scenario.

        Wine, X or the wineserver failing to come up under load exits non-zero with no
        result file, exactly like a crashing game. Reporting both as `crash` sent an
        investigation hunting for a port bug that was not there (see
        imperialism-decomp-gdqr), so the two are now distinguishable from the result
        line alone.
        """
        self.assertEqual(
            classify_exit(-11, False, saw_heartbeat=False), "exited_before_first_heartbeat"
        )

    def test_liveness_defaults_to_true_for_callers_that_cannot_observe_it(self) -> None:
        self.assertEqual(classify_exit(-11, False), "crash")

    def test_clean_exit_without_result_is_exited_without_result(self) -> None:
        self.assertEqual(classify_exit(0, False), "exited_without_result")


class CompareMapStateTests(unittest.TestCase):
    def test_matching_snapshot_passes(self) -> None:
        state = {"terrain_counts": [1, 2], "owned_tiles": [3], "wrap": 1}
        self.assertEqual(compare_map_state(dict(state), dict(state))["status"], "passed")

    def test_extra_actual_fields_are_ignored(self) -> None:
        expected = {"wrap": 1}
        actual = {"wrap": 1, "economic_turn": 4}
        self.assertEqual(compare_map_state(actual, expected)["status"], "passed")

    def test_mismatch_reports_expected_and_actual(self) -> None:
        comparison = compare_map_state({"wrap": 0}, {"wrap": 1, "missing": [1]})
        self.assertEqual(comparison["status"], "failed")
        self.assertEqual(
            comparison["differences"]["wrap"], {"expected": 1, "actual": 0}
        )
        self.assertEqual(
            comparison["differences"]["missing"], {"expected": [1], "actual": None}
        )


class PruneOldRunDirsTests(unittest.TestCase):
    def test_keeps_newest_bundles_and_other_tests_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result_dir = Path(tmp)
            for day in range(1, 13):
                (result_dir / f"boot_managers-202607{day:02d}T000000Z-1").mkdir()
            (result_dir / "random_game_enters_map-20260701T000000Z-1").mkdir()
            (result_dir / "boot_managers.json").write_text("{}")
            prune_old_run_dirs(result_dir, "boot_managers", keep=10)
            kept = sorted(p.name for p in result_dir.iterdir())
            self.assertEqual(len([n for n in kept if n.startswith("boot_managers-")]), 10)
            self.assertNotIn("boot_managers-20260701T000000Z-1", kept)
            self.assertNotIn("boot_managers-20260702T000000Z-1", kept)
            self.assertIn("boot_managers-20260703T000000Z-1", kept)
            self.assertIn("random_game_enters_map-20260701T000000Z-1", kept)
            self.assertIn("boot_managers.json", kept)


class NoProgressBudgetTests(unittest.TestCase):
    def test_budget_exceeds_the_driver_phase_timeout(self) -> None:
        self.assertGreater(no_progress_budget_seconds(60_000), 60.0)

    def test_budget_scales_with_the_phase_timeout(self) -> None:
        self.assertGreater(
            no_progress_budget_seconds(120_000), no_progress_budget_seconds(60_000)
        )


if __name__ == "__main__":
    unittest.main()
