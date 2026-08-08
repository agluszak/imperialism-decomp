#!/usr/bin/env python3
"""Contracts for normalized runtime determinism and leakage classification."""

from __future__ import annotations

import unittest

from tools.runtime.determinism import classify_leaks, normalized_observation


class RuntimeDeterminismTests(unittest.TestCase):
    @staticmethod
    def _result() -> dict:
        return {
            "name": "sample",
            "seed": 1,
            "status": "passed",
            "host": {"artifact_path": "/tmp/one", "duration_seconds": 42},
            "captures": {
                "map_state": {"wrap": 3},
                "coarse_map_generation": {"tiles": [[1]]},
                "game_state": {"turn": 4},
            },
        }

    def test_normalization_removes_host_timing_and_artifact_noise(self) -> None:
        left = self._result()
        right = self._result()
        right["host"] = {"artifact_path": "/tmp/two", "duration_seconds": 99}
        self.assertEqual(normalized_observation(left), normalized_observation(right))

    def test_leak_classification_names_each_boundary(self) -> None:
        baseline = {"sample": self._result()}

        self.assertEqual(
            classify_leaks(baseline, {}, "same_order")[0]["kind"],
            "registry_leakage",
        )

        rng = self._result()
        rng["seed"] = 2
        self.assertIn(
            "rng_leakage",
            {item["kind"] for item in classify_leaks(baseline, {"sample": rng}, "same_order")},
        )

        save = self._result()
        save["captures"]["map_state"] = {"wrap": 4}
        save_kinds = {
            item["kind"]
            for item in classify_leaks(baseline, {"sample": save}, "same_order")
        }
        self.assertIn("save_leakage", save_kinds)
        self.assertIn("observation_leakage", save_kinds)

        changed = self._result()
        changed["captures"]["game_state"] = {"turn": 5}
        self.assertIn(
            "order_leakage",
            {
                item["kind"]
                for item in classify_leaks(
                    baseline, {"sample": changed}, "reverse_order"
                )
            },
        )
        self.assertIn(
            "debugger_leakage",
            {
                item["kind"]
                for item in classify_leaks(baseline, {"sample": changed}, "gdb")
            },
        )

    def test_semantic_captures_are_part_of_the_byte_stable_observation(self) -> None:
        left = self._result()
        right = self._result()
        right["captures"]["coarse_map_generation"]["tiles"][0][0] = 2
        self.assertNotEqual(normalized_observation(left), normalized_observation(right))


if __name__ == "__main__":
    unittest.main()
