#!/usr/bin/env python3
"""Tests for the runtime-test runner's host-side failure classification."""

from __future__ import annotations

import unittest

from tools.runtime.runtime_tests import (
    classify_exit,
    classify_poll,
    no_progress_budget_seconds,
)


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
            classify_poll(None, None, 90.0, process_age_seconds=61.0),
            "heartbeat_stopped",
        )

    def test_fresh_heartbeat_with_recent_progress_is_healthy(self) -> None:
        self.assertIsNone(classify_poll(heartbeat(30_000, 29_000), 0.5, 90.0))

    def test_stale_heartbeat_is_heartbeat_stopped(self) -> None:
        self.assertEqual(
            classify_poll(heartbeat(30_000, 29_000), 16.0, 90.0),
            "heartbeat_stopped",
        )

    def test_stale_check_precedes_no_progress_check(self) -> None:
        self.assertEqual(
            classify_poll(heartbeat(500_000, 0), 20.0, 90.0),
            "heartbeat_stopped",
        )

    def test_fresh_heartbeat_without_progress_is_pump_alive(self) -> None:
        self.assertEqual(
            classify_poll(heartbeat(200_000, 1_000), 0.5, 90.0),
            "pump_alive_no_semantic_progress",
        )

    def test_no_progress_budget_is_inclusive_at_the_boundary(self) -> None:
        self.assertIsNone(classify_poll(heartbeat(91_000, 1_000), 0.5, 90.0))

    def test_malformed_heartbeat_fields_are_tolerated(self) -> None:
        self.assertIsNone(classify_poll({"phase": "boot"}, 0.5, 90.0))
        self.assertIsNone(
            classify_poll({"elapsed_ms": "junk", "last_progress_ms": 0}, 0.5, 90.0)
        )


class ClassifyExitTests(unittest.TestCase):
    def test_result_file_present_is_not_classified(self) -> None:
        self.assertIsNone(classify_exit(0, True))
        self.assertIsNone(classify_exit(5, True))

    def test_nonzero_exit_without_result_is_crash(self) -> None:
        self.assertEqual(classify_exit(-11, False), "crash")

    def test_clean_exit_without_result_is_exited_without_result(self) -> None:
        self.assertEqual(classify_exit(0, False), "exited_without_result")


class NoProgressBudgetTests(unittest.TestCase):
    def test_budget_exceeds_the_driver_phase_timeout(self) -> None:
        self.assertGreater(no_progress_budget_seconds(60_000), 60.0)

    def test_budget_scales_with_the_phase_timeout(self) -> None:
        self.assertGreater(
            no_progress_budget_seconds(120_000), no_progress_budget_seconds(60_000)
        )


if __name__ == "__main__":
    unittest.main()
