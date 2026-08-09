#!/usr/bin/env python3
"""Contracts for the pending-news order retail differential."""

from __future__ import annotations

import unittest

from tools.runtime.pending_news_order_differential import TRIALS, first_difference


class PendingNewsOrderDifferentialTests(unittest.TestCase):
    def test_trials_distinguish_append_prepend_and_payload_sorting(self) -> None:
        self.assertEqual(
            [(trial.name, trial.counterparts) for trial in TRIALS],
            [
                ("forward", (1, 2)),
                ("reverse", (2, 1)),
                ("forward_repeat", (1, 2)),
            ],
        )

    def test_first_difference_reports_semantic_queue_position(self) -> None:
        retail = {
            "forward": {
                "queue_after_each_insert": [
                    [{"counterpart": 1}],
                    [{"counterpart": 1}, {"counterpart": 2}],
                ]
            }
        }
        recomp = {
            "forward": {
                "queue_after_each_insert": [
                    [{"counterpart": 1}],
                    [{"counterpart": 2}, {"counterpart": 1}],
                ]
            }
        }
        self.assertEqual(
            first_difference(retail, recomp),
            {
                "path": "$.forward.queue_after_each_insert[1][0].counterpart",
                "retail": 1,
                "recomp": 2,
            },
        )


if __name__ == "__main__":
    unittest.main()
