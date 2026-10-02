"""Saved-report deltas never infer source causality or silently change populations."""

import unittest

from tools.reccmp.report import call_queue, report_delta


def summary(rows: list[dict], retail: str = "retail") -> dict:
    return {
        "target": "IMPERIALISM",
        "inputs": {"orig": {"sha256": retail}},
        "functions": rows,
    }


class CompareReportTests(unittest.TestCase):
    def test_delta_reports_population_changes_separately(self) -> None:
        before = summary(
            [
                {"orig": "0x1", "outcome": "differences"},
                {"orig": "0x2", "outcome": "no-differences"},
            ]
        )
        after = summary(
            [
                {"orig": "0x1", "outcome": "no-differences"},
                {"orig": "0x3", "outcome": "unpaired"},
            ]
        )
        self.assertEqual(
            report_delta(after, before),
            {
                "shared_functions": 1,
                "added_to_dataset": ["0x3"],
                "removed_from_dataset": ["0x2"],
                "outcome_transitions": [
                    {"base": "differences", "head": "no-differences", "count": 1}
                ],
            },
        )

    def test_delta_rejects_different_retail_inputs(self) -> None:
        with self.assertRaises(ValueError):
            report_delta(summary([], "a"), summary([], "b"))

    def test_call_queue_retains_incomplete_body_as_unknown(self) -> None:
        census = {
            "functions": [
                {"address": "0x1", "orig": {"calls": None}, "recomp": {"calls": []}},
                {"address": "0x2", "orig": {"calls": []}, "recomp": {"calls": []}},
            ]
        }
        self.assertEqual(
            call_queue(census), [{"orig": "0x1", "category": "incomplete-body"}]
        )


if __name__ == "__main__":
    unittest.main()
