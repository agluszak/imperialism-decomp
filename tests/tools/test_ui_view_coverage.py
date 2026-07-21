from __future__ import annotations

from collections import Counter
from pathlib import Path
import unittest

from tools.workflow.ui_view_coverage import (
    REPORT_PATH,
    build_coverage_rows,
    render_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class UiViewCoverageTests(unittest.TestCase):
    def test_every_committed_mac_view_has_one_disposition(self) -> None:
        rows, errors = build_coverage_rows(REPO_ROOT)

        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 121)
        self.assertEqual(len({row.key for row in rows}), 121)
        self.assertTrue(all(row.evidence and row.bead for row in rows))

    def test_coverage_counts_keep_unresolved_work_visible(self) -> None:
        rows, errors = build_coverage_rows(REPO_ROOT)
        self.assertEqual(errors, [])

        self.assertEqual(
            Counter(row.status for row in rows),
            {
                "generated_turn_event_factory": 93,
                "windows_runtime_gap": 1,
                "windows_alternate_path": 1,
                "excluded_mac_only_or_obsolete": 10,
                "excluded_mac_test_debug_or_framework": 16,
            },
        )

    def test_minimap_uses_the_dynamic_windows_construction_path(self) -> None:
        rows, errors = build_coverage_rows(REPO_ROOT)
        self.assertEqual(errors, [])
        minimap = next(row for row in rows if row.key.text() == "Linger.rsrc:2050")

        self.assertEqual(minimap.status, "windows_alternate_path")
        self.assertTrue(any("assertion line number" in item for item in minimap.evidence))
        self.assertTrue(any("0x00599cf0" in item for item in minimap.evidence))

    def test_confirmed_runtime_gaps_are_owned_as_functional_parity_cases(self) -> None:
        rows, errors = build_coverage_rows(REPO_ROOT)
        self.assertEqual(errors, [])
        runtime_gap_resources = {
            "Linger.rsrc:2021",
            "Startup.rsrc:965",
            "Transport.rsrc:3901",
        }
        recovered = {row.key.text(): row for row in rows if row.key.text() in runtime_gap_resources}

        self.assertEqual(set(recovered), runtime_gap_resources)
        self.assertTrue(
            all(row.status == "generated_turn_event_factory" for row in recovered.values())
        )
        self.assertTrue(
            all("functional-parity case" in row.evidence[0] for row in recovered.values())
        )

    def test_committed_report_is_current(self) -> None:
        rows, errors = build_coverage_rows(REPO_ROOT)
        self.assertEqual(errors, [])
        committed = (REPO_ROOT / REPORT_PATH).read_text(encoding="utf-8")

        self.assertEqual(committed, render_report(rows))


if __name__ == "__main__":
    unittest.main()
