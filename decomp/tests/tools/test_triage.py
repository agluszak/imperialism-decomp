"""Structured reccmp diagnosis rendering for `just triage`."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.reccmp.triage import load_entities, main, render_entity

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


class TriageCliTests(unittest.TestCase):
    def test_main_accepts_target_and_build_dir_and_loads_data_list(self) -> None:
        row = entity("exact")
        with patch(
            "tools.reccmp.triage.run_report", return_value=[row]
        ) as report, patch(
            "tools.reccmp.triage.names_by_address", return_value={}
        ), patch(
            "tools.reccmp.triage.ownership_by_address", return_value=OWNERSHIP
        ):
            code = main(
                [
                    "--target",
                    "IMPERIALISM",
                    "--build-dir",
                    "build-msvc500",
                    "0x401000",
                ]
            )
        self.assertEqual(code, 0)
        report.assert_called_once()
        args, kwargs = report.call_args
        self.assertEqual(args[0], "IMPERIALISM")
        self.assertTrue(kwargs["diet"])
        self.assertEqual(list(kwargs["orig_addresses"]), [0x401000])

    def test_report_json_reads_data_list(self) -> None:
        row = entity("exact")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"data": [row]}), encoding="utf-8")
            entities = load_entities(
                target="IMPERIALISM",
                build_dir=Path("build-msvc500"),
                report_json=path,
                addrs=[0x401000],
            )
        self.assertEqual(entities[0x401000]["name"], "TExample::Run")


if __name__ == "__main__":
    unittest.main()
