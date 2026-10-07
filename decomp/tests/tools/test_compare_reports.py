"""Saved-report deltas never infer source causality or silently change populations."""

import unittest

from tools.reccmp.report import call_queue, reference_groups, report_delta


def scored(address: str, outcome: str, score: float | None = None, name: str = "f") -> dict:
    return {
        "orig": address,
        "name": name,
        "outcome": outcome,
        "selected_pass": "ordinary",
        "passes": {"ordinary": {"similarity": score}},
    }


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
                scored("0x1", "differences", 0.5),
                scored("0x2", "no-differences", 1.0),
                scored("0x4", "differences", 0.9, "g"),
            ]
        )
        after = summary(
            [
                scored("0x1", "no-differences", 1.0),
                scored("0x3", "unpaired"),
                scored("0x4", "differences", 0.6, "g"),
            ]
        )
        delta = report_delta(after, before)
        self.assertEqual(
            delta["similarity"],
            {
                "improved": 1,
                "regressed": 1,
                "net": 0.2,
                "largest_regressions": [{"orig": "0x4", "name": "g", "base": 0.9, "head": 0.6}],
                "largest_improvements": [{"orig": "0x1", "name": "f", "base": 0.5, "head": 1.0}],
            },
        )
        del delta["similarity"]
        self.assertEqual(
            delta,
            {
                "shared_functions": 2,
                "added_to_dataset": ["0x3"],
                "removed_from_dataset": ["0x2"],
                "outcome_transitions": [
                    {"base": "differences", "head": "differences", "count": 1},
                    {"base": "differences", "head": "no-differences", "count": 1},
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

    def test_reference_groups_report_measured_shared_evidence(self) -> None:
        def row(address, name, outcome, data):
            return {
                "orig": address,
                "name": name,
                "outcome": outcome,
                "source": {"path": "src/Owner.cpp"},
                "selected_pass": "ordinary",
                "passes": {"ordinary": {"data": data}},
            }

        shared = {"object": {"orig": "0x10", "name": "sharedObject"}}
        report = summary(
            [
                row("0x1", "First", "differences", [{"object": None}, shared]),
                row("0x2", "Second", "analysis-failed", [shared]),
                row("0x3", "Clean", "no-differences", []),
            ]
        )
        census = {
            "functions": [
                {
                    "address": address,
                    "orig": {
                        "calls": [
                            {
                                "identity": "orig:0x20",
                                "name": "SharedCallee",
                            }
                        ]
                    },
                }
                for address in ("0x1", "0x2", "0x3")
            ]
        }
        groups = reference_groups(report, census)
        expected = {"0x1", "0x2"}
        for category in groups.values():
            self.assertEqual(
                {item["orig"] for item in category["groups"][0]["functions"]},
                expected,
            )
            self.assertIn("non-clean authored", category["measure"])


if __name__ == "__main__":
    unittest.main()
