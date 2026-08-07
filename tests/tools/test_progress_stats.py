#!/usr/bin/env python3
"""Regression tests for typed reccmp progress accounting."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reccmp.compare.diagnosis import ComparisonAnalysis
from reccmp.compare.report import ReccmpComparedEntity
from reccmp.types import EntityType

from tools.reccmp.progress_stats import (
    baseline_provenance_error,
    build_progress_report,
    clamp_stub_count_ratchet,
    function_changes,
    generated_stub_report_errors,
    parse_report_counts,
    parse_roadmap_counts,
    parse_report_functions,
    report_cache_is_current,
    run_progress_report,
    ui_factory_fidelity,
    unapproved_unpaired,
    write_report_cache,
)


def make_match(
    name: str,
    address: int,
    ratio: float,
    *,
    entity_type: EntityType = EntityType.FUNCTION,
    stub: bool = False,
) -> ReccmpComparedEntity:
    analysis = (
        ComparisonAnalysis.exact()
        if ratio == 1.0
        else ComparisonAnalysis.inconclusive("analysis_limit")
    )
    return ReccmpComparedEntity(
        type=entity_type,
        orig_addr=address,
        recomp_addr=address + 0x1000,
        name=name,
        accuracy=ratio,
        analysis=analysis,
        is_stub=stub,
    )


class ProgressStatsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.report_path = Path(self.tempdir.name) / "report.json"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_report(self, matches: list[ReccmpComparedEntity]) -> None:
        report = build_progress_report("Imperialism.exe", matches)
        rows = []
        for entity in report.entities.values():
            rows.append(
                {
                    "address": f"{entity.orig_addr:#x}",
                    "name": entity.name,
                    "matching": entity.accuracy,
                    "comparison": {
                        "status": entity.analysis.status.value,
                        "semantic_similarity": entity.analysis.semantic_similarity,
                    },
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
                "semantic_scored_fun_count": 1,
                "semantic_fallback_fun_count": 1,
                "semantic_score_coverage_pct": 50.0,
                "semantic_scored_bytes": 1,
                "semantic_fallback_bytes": 1,
                "semantic_score_byte_coverage_pct": 50.0,
                "semantic_size_weighted_matching_pct": 62.5,
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
        self.assertAlmostEqual(counts["semantic_size_weighted_matching_pct"], 43.75)

    def test_semantic_size_weighted_similarity_uses_partial_scores_with_fallback(self) -> None:
        rows = [
            {
                "address": "0x401000",
                "matching": 1.0,
                "comparison": {"status": "exact", "semantic_similarity": 1.0},
            },
            {
                "address": "0x402000",
                "matching": 0.2,
                "comparison": {"status": "effective", "semantic_similarity": 1.0},
            },
            {
                "address": "0x403000",
                "matching": 0.25,
                "comparison": {"status": "mismatch", "semantic_similarity": 0.75},
            },
            {
                "address": "0x404000",
                "matching": 0.5,
                "comparison": {"status": "mismatch", "semantic_similarity": None},
            },
        ]
        self.report_path.write_text(json.dumps({"data": rows}), encoding="utf-8")

        counts = parse_report_counts(
            self.report_path,
            sizes={0x401000: 100, 0x402000: 100, 0x403000: 300, 0x404000: 500},
        )

        self.assertAlmostEqual(counts["size_weighted_matching_pct"], 52.5)
        self.assertAlmostEqual(counts["semantic_size_weighted_matching_pct"], 67.5)
        self.assertEqual(counts["semantic_scored_fun_count"], 3)
        self.assertEqual(counts["semantic_fallback_fun_count"], 1)
        self.assertEqual(counts["semantic_score_coverage_pct"], 75.0)
        self.assertEqual(counts["semantic_scored_bytes"], 500)
        self.assertEqual(counts["semantic_fallback_bytes"], 500)
        self.assertEqual(counts["semantic_score_byte_coverage_pct"], 50.0)

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
                "semantic_scored_fun_count": 1,
                "semantic_fallback_fun_count": 1,
                "semantic_score_coverage_pct": 50.0,
                "semantic_scored_bytes": 1,
                "semantic_fallback_bytes": 1,
                "semantic_score_byte_coverage_pct": 50.0,
                "semantic_size_weighted_matching_pct": 62.5,
                "avg_matching_pct": 62.5,
                "size_weighted_matching_pct": 62.5,
            },
        )
        self.assertEqual(
            set(parse_report_functions(self.report_path)),
            {"0x401000", "0x402000"},
        )

    def test_function_names_drop_report_rendering_whitespace(self) -> None:
        self.write_report([make_match("CString::operator char const * ", 0x401000, 1.0)])

        self.assertEqual(
            parse_report_functions(self.report_path)["0x401000"]["n"],
            "CString::operator char const *",
        )

    def test_every_generated_placeholder_is_reported_as_a_stub(self) -> None:
        self.write_report(
            [
                make_match("stub", 0x410000, 1.0, stub=True),
                make_match("misclassified", 0x420000, 1.0),
            ]
        )
        stub_rows = [
            (0x410000, "stub", ""),
            (0x420000, "misclassified", ""),
            (0x430000, "missing", ""),
            (0x401000, "ilt_thunk", ""),
        ]

        self.assertEqual(
            generated_stub_report_errors(self.report_path, stub_rows),
            [
                "0x00430000: generated placeholder missing from report",
                "0x00420000: generated placeholder reported without stub=true",
            ],
        )

    def test_function_changes_identifies_regressions_and_newly_unpaired(self) -> None:
        baseline = {
            "0x410000": {"m": 1.0, "n": "regressed"},
            "0x420000": {"m": 0.5, "n": "unpaired"},
        }
        current = {"0x410000": {"m": 0.25, "n": "regressed"}}

        regressed, unpaired, improved, newly_paired = function_changes(current, baseline)

        self.assertEqual(regressed, [("0x410000", "regressed", 1.0, 0.25)])
        self.assertEqual(unpaired, [("0x420000", "unpaired", 0.5)])
        self.assertEqual(improved, 0)
        self.assertEqual(newly_paired, 0)

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

    def test_unpaired_baseline_migration_requires_each_address(self) -> None:
        rows = [
            ("0x00401000", "first", 1.0),
            ("0x00402000", "second", 0.5),
        ]
        self.assertEqual(
            unapproved_unpaired(rows, {0x00401000}),
            [("0x00402000", "second", 0.5)],
        )


class StubCountRatchetTests(unittest.TestCase):
    """stats-baseline-update must not re-arm the stub ratchet at a raised height.

    The commit policy runs stats-baseline-update before every commit, so a rise that
    rode along in the snapshot would disarm `just stub-count-gate` on exactly the
    commit that caused it (imperialism-decomp-3s7y).
    """

    def test_rise_is_held_back_so_the_gate_still_fires(self) -> None:
        entry = {"stub_count": 720, "exact_fun_count": 4350}
        with patch.dict("os.environ", {}, clear=True):
            notice = clamp_stub_count_ratchet(entry, {"stub_count": 355})
        self.assertEqual(entry["stub_count"], 355)
        self.assertIn("held at 355", notice or "")
        self.assertIn("ALLOW_POLICY_BASELINE_UPDATE=1", notice or "")

    def test_rise_is_recorded_with_explicit_approval(self) -> None:
        entry = {"stub_count": 720}
        with patch.dict("os.environ", {"ALLOW_POLICY_BASELINE_UPDATE": "1"}, clear=True):
            notice = clamp_stub_count_ratchet(entry, {"stub_count": 355})
        self.assertEqual(entry["stub_count"], 720)
        self.assertIn("RAISED", notice or "")

    def test_fall_ratchets_down_without_approval(self) -> None:
        entry = {"stub_count": 300}
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(clamp_stub_count_ratchet(entry, {"stub_count": 355}))
        self.assertEqual(entry["stub_count"], 300)

    def test_equal_count_and_missing_baseline_are_untouched(self) -> None:
        entry = {"stub_count": 355}
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(clamp_stub_count_ratchet(entry, {"stub_count": 355}))
            self.assertIsNone(clamp_stub_count_ratchet(entry, None))
            self.assertIsNone(clamp_stub_count_ratchet(entry, {}))
        self.assertEqual(entry["stub_count"], 355)


    def test_clean_tree_requires_matching_source_model_fingerprint(self) -> None:
        entry = {"source_model_fingerprint": "current"}
        self.assertIsNone(
            baseline_provenance_error(
                entry, {"source_model_fingerprint": "old"}, False
            )
        )
        self.assertIn(
            "does not describe",
            baseline_provenance_error(
                entry, {"source_model_fingerprint": "old"}, True
            )
            or "",
        )
        self.assertIsNone(
            baseline_provenance_error(
                entry, {"source_model_fingerprint": "current"}, True
            )
        )


class UiFactoryFidelityTests(unittest.TestCase):
    """The generated factories are ~18% of paired bytes; the aggregate is now tracked.

    imperialism-decomp-wqfq: a per-function ratchet already stopped them getting worse,
    but the headline number was recomputed by hand whenever someone asked.
    """

    def _report(self, directory: Path, rows: list[dict]) -> Path:
        path = directory / "report.json"
        path.write_text(json.dumps({"data": rows}), encoding="utf-8")
        return path

    def _recipes(self, *addresses: int):
        return [SimpleNamespace(address=address) for address in addresses]

    def test_weighted_by_original_size_not_by_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory, [
                {"address": "0x1000", "matching": 1.0, "type": 1, "comparison": {"status": "mismatch"}},
                {"address": "0x2000", "matching": 0.0, "type": 1, "comparison": {"status": "mismatch"}},
            ])
            with patch("tools.ui_codegen.load_recipes",
                       return_value=self._recipes(0x1000, 0x2000)):
                # 100% over 100 bytes and 0% over 900 -> 10%, not the 50% a plain mean gives.
                result = ui_factory_fidelity(report, {0x1000: 100, 0x2000: 900}, directory)
        self.assertEqual(result["ui_factory_count"], 2)
        self.assertEqual(result["ui_factory_paired_count"], 2)
        self.assertAlmostEqual(result["ui_factory_weighted_pct"], 10.0, places=6)

    def test_unpaired_factories_are_counted_but_not_weighted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory, [{"address": "0x1000", "matching": 0.5, "type": 1, "comparison": {"status": "mismatch"}}])
            with patch("tools.ui_codegen.load_recipes",
                       return_value=self._recipes(0x1000, 0x2000)):
                result = ui_factory_fidelity(report, {0x1000: 10}, directory)
        self.assertEqual(result["ui_factory_count"], 2)
        self.assertEqual(result["ui_factory_paired_count"], 1)
        self.assertAlmostEqual(result["ui_factory_weighted_pct"], 50.0, places=6)

    def test_missing_sizes_fall_back_to_equal_weight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory, [
                {"address": "0x1000", "matching": 1.0, "type": 1, "comparison": {"status": "mismatch"}},
                {"address": "0x2000", "matching": 0.0, "type": 1, "comparison": {"status": "mismatch"}},
            ])
            with patch("tools.ui_codegen.load_recipes",
                       return_value=self._recipes(0x1000, 0x2000)):
                result = ui_factory_fidelity(report, None, directory)
        self.assertAlmostEqual(result["ui_factory_weighted_pct"], 50.0, places=6)

    def test_no_recipes_contributes_no_metric(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = self._report(directory, [])
            with patch("tools.ui_codegen.load_recipes", return_value=[]):
                self.assertEqual(ui_factory_fidelity(report, {}, directory), {})

    def test_typed_roadmap_separates_imports_and_actionable_states(self) -> None:
        roadmap = Path(tempfile.mkdtemp()) / "roadmap.csv"
        roadmap.write_text(
            "orig_addr,recomp_addr,row_type,pairing_state\n"
            "0x410000,0x510000,function,paired\n"
            "0x411000,,function,original_alias\n"
            ",0x512000,function,recomp_duplicate\n"
            "0x420000,,data,unexplained\n"
            "0x430000,0x530000,string,paired\n"
            "0x440000,,label,unexplained\n"
            "0x450000,,float,unexplained\n"
            "0x460000,0x560000,import,paired\n"
            "0x470000,,import,unexplained\n"
            "0x480000,0x580000,import_thunk,paired\n"
            "0x490000,,import_thunk,alias\n"
            "0x4a0000,,vtable,duplicate\n",
            encoding="utf-8",
        )

        counts = parse_roadmap_counts(roadmap)

        self.assertEqual(counts["original_function_alias_count"], 1)
        self.assertEqual(counts["recomp_function_duplicate_count"], 1)
        self.assertEqual(counts["original_import_count"], 2)
        self.assertEqual(counts["paired_import_count"], 1)
        self.assertEqual(counts["unexplained_import_count"], 1)
        self.assertEqual(counts["original_import_thunk_count"], 2)
        self.assertEqual(counts["paired_import_thunk_count"], 1)
        self.assertEqual(counts["alias_import_thunk_count"], 1)
        self.assertEqual(counts["duplicate_vtable_count"], 1)
        self.assertEqual(counts["actionable_non_fun_count"], 7)
        self.assertEqual(counts["actionable_non_fun_covered_count"], 5)
        self.assertEqual(counts["actionable_non_fun_unexplained_count"], 2)
        self.assertEqual(counts["expected_unpaired_label_count"], 1)
        self.assertEqual(counts["expected_unpaired_float_count"], 1)

    def test_legacy_abbreviated_roadmap_is_rejected(self) -> None:
        roadmap = Path(tempfile.mkdtemp()) / "roadmap.csv"
        roadmap.write_text(
            "orig_addr,recomp_addr,row_type\n0x410000,0x510000,imp\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "typed schema"):
            parse_roadmap_counts(roadmap)


if __name__ == "__main__":
    unittest.main()
