#!/usr/bin/env python3
"""Regression tests for complete, function-only reccmp progress accounting."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reccmp.compare.diagnosis import ComparisonAnalysis
from reccmp.compare.diff import DiffReport, EntityCompareResult
from reccmp.types import EntityType

from tools.reccmp.progress_stats import (
    build_progress_report,
    parse_report_counts,
    parse_report_functions,
    report_cache_is_current,
    run_progress_report,
    write_report_cache,
)


def make_match(
    name: str,
    address: int,
    ratio: float,
    *,
    entity_type: EntityType = EntityType.FUNCTION,
    stub: bool = False,
) -> DiffReport:
    analysis = (
        ComparisonAnalysis.exact()
        if ratio == 1.0
        else ComparisonAnalysis.inconclusive("analysis_limit")
    )
    return DiffReport(
        match_type=entity_type,
        orig_addr=address,
        recomp_addr=address + 0x1000,
        name=name,
        result=EntityCompareResult(match_ratio=ratio, analysis=analysis),
        is_stub=stub,
    )


class ProgressStatsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.report_path = Path(self.tempdir.name) / "report.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_report(self, matches: list[DiffReport]) -> None:
        report = build_progress_report("Imperialism.exe", matches)
        rows = []
        for entity in report.entities.values():
            rows.append(
                {
                    "address": entity.orig_addr,
                    "name": entity.name,
                    "matching": entity.accuracy,
                    "comparison": {"status": entity.analysis.status.value},
                    "type": int(entity.type),
                    **({"stub": True} if entity.is_stub else {}),
                }
            )
        self.report_path.write_text(json.dumps({"data": rows}), encoding="utf-8")

    def test_report_keeps_exact_and_mismatching_library_functions(self) -> None:
        matches = [
            make_match("CObject::AssertValid", 0x401000, 1.0),
            make_match("CString::Format", 0x402000, 0.25),
        ]
        report = build_progress_report("Imperialism.exe", matches)

        self.assertEqual(
            {entity.name for entity in report.entities.values()},
            {"CObject::AssertValid", "CString::Format"},
        )

    @patch("tools.reccmp.progress_stats.Compare.from_target")
    @patch("tools.reccmp.progress_stats.RecCmpProject.from_directory")
    def test_runner_does_not_apply_target_ignore_functions(
        self, from_directory, from_target
    ) -> None:
        target = SimpleNamespace(
            original_path=Path("Imperialism.exe"),
            report_config=SimpleNamespace(
                ignore_functions=["CObject::AssertValid", "CString::Format"]
            ),
        )
        from_directory.return_value.get.return_value = target
        from_target.return_value.compare_all.return_value = [
            make_match("CObject::AssertValid", 0x401000, 1.0),
            make_match("CString::Format", 0x402000, 0.25),
        ]

        run_progress_report(
            "IMPERIALISM",
            Path(self.tempdir.name),
            self.report_path,
            Path(self.tempdir.name) / "report.log",
        )

        self.assertEqual(
            parse_report_counts(self.report_path),
            {
                "compared_fun_count": 2,
                "exact_fun_count": 1,
                "not_exact_compared_count": 1,
                "avg_matching_pct": 62.5,
                "size_weighted_matching_pct": 62.5,
            },
        )

    def test_size_weighted_similarity_weights_by_original_size(self) -> None:
        self.write_report(
            [
                make_match("tiny_exact", 0x401000, 1.0),
                make_match("big_mismatch", 0x402000, 0.25),
            ]
        )
        counts = parse_report_counts(
            self.report_path, sizes={0x401000: 100, 0x402000: 300}
        )
        # (1.0*100 + 0.25*300) / 400 = 43.75 — the big weak body dominates,
        # unlike the unweighted mean (62.5).
        self.assertEqual(counts["avg_matching_pct"], 62.5)
        self.assertAlmostEqual(counts["size_weighted_matching_pct"], 43.75)

    def test_counts_only_functions_and_excludes_stubs(self) -> None:
        self.write_report(
            [
                make_match("exact", 0x401000, 1.0),
                make_match("mismatch", 0x402000, 0.25),
                make_match(
                    "Class::`vftable'",
                    0x403000,
                    1.0,
                    entity_type=EntityType.VTABLE,
                ),
                make_match("stub", 0x404000, 1.0, stub=True),
            ]
        )

        self.assertEqual(
            parse_report_counts(self.report_path),
            {
                "compared_fun_count": 2,
                "exact_fun_count": 1,
                "not_exact_compared_count": 1,
                "avg_matching_pct": 62.5,
                "size_weighted_matching_pct": 62.5,
            },
        )
        self.assertEqual(
            set(parse_report_functions(self.report_path)),
            {"0x401000", "0x402000"},
        )

    def test_report_cache_requires_matching_inputs_and_untampered_outputs(self) -> None:
        cache_path = Path(self.tempdir.name) / "inputs.json"
        roadmap_path = Path(self.tempdir.name) / "roadmap.csv"
        log_path = Path(self.tempdir.name) / "report.log"
        roadmap_path.write_text("roadmap", encoding="utf-8")
        self.report_path.write_text('{"data": []}', encoding="utf-8")
        log_path.write_text("log", encoding="utf-8")
        outputs = {
            "roadmap_csv": roadmap_path,
            "report_json": self.report_path,
            "report_log": log_path,
        }
        inputs = {"Imperialism.exe": "original-hash", "src/TView.cpp": "source-hash"}

        write_report_cache(cache_path, "IMPERIALISM", inputs, outputs)
        self.assertTrue(
            report_cache_is_current(cache_path, "IMPERIALISM", inputs, outputs)
        )
        self.assertFalse(
            report_cache_is_current(
                cache_path,
                "IMPERIALISM",
                {**inputs, "src/TView.cpp": "changed"},
                outputs,
            )
        )

        self.report_path.write_text('{"data": ["tampered"]}', encoding="utf-8")
        self.assertFalse(
            report_cache_is_current(cache_path, "IMPERIALISM", inputs, outputs)
        )


if __name__ == "__main__":
    unittest.main()
