"""Structured reccmp diagnosis rendering for `just triage`."""

from __future__ import annotations

import unittest

from tools.reccmp.triage import render_entity

OWNERSHIP = {0x401000: "manual"}
NAMES: dict[int, str] = {}


def entity(
    status: str,
    *,
    difference=None,
    reasons=None,
    inconclusive=None,
    semantic_similarity=None,
):
    return {
        "address": "0x401000",
        "name": "TExample::Run",
        "matching": 1.0 if status == "exact" else 0.4286,
        "comparison": {
            "status": status,
            "effective_reasons": reasons or [],
            "difference": difference,
            "inconclusive_reason": inconclusive,
            "inconclusive_location": None,
            "semantic_similarity": semantic_similarity,
        },
    }


class TriageRenderTests(unittest.TestCase):
    def test_exact_output(self) -> None:
        text = render_entity(entity("exact"), names=NAMES, ownership=OWNERSHIP)
        self.assertIn("exact match", text)
        self.assertIn("[manual]", text)

    def test_effective_lists_reasons(self) -> None:
        text = render_entity(
            entity("effective", reasons=["register_allocation", "padding"]),
            names=NAMES,
            ownership=OWNERSHIP,
        )
        self.assertIn("register allocation", text)
        self.assertIn("alignment padding", text)
        self.assertIn("no action needed", text)

    def test_mismatch_prints_structured_difference(self) -> None:
        value = entity(
            "mismatch",
            difference={
                "kind": "memory_value",
                "orig": {
                    "instruction_index": 2,
                    "address": 0x401020,
                    "facts": {"value": 1},
                },
                "recomp": {
                    "instruction_index": 3,
                    "address": 0x501020,
                    "facts": {"value": 2},
                },
            },
            semantic_similarity=0.875,
        )
        text = render_entity(value, names=NAMES, ownership=OWNERSHIP)
        self.assertIn("mismatch (memory value", text)
        self.assertIn("87.50% semantic", text)
        self.assertIn("orig facts", text)

    def test_inconclusive_prints_reason(self) -> None:
        text = render_entity(
            entity("inconclusive", inconclusive="alignment_failure"),
            names=NAMES,
            ownership=OWNERSHIP,
        )
        self.assertIn("inconclusive: alignment failure", text)


if __name__ == "__main__":
    unittest.main()
