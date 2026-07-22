from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.ghidra.data_function_pointers import (
    REPORT_PATH,
    candidate_rank,
    is_ui_relevant,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class DataFunctionPointerTests(unittest.TestCase):
    def test_ui_ranking_prefers_unowned_zero_call_large_targets(self) -> None:
        rows = [
            {
                "target": "0x00400001",
                "ui_relevant": True,
                "owner": "src/game/Foo.cpp",
                "call_xref_count": 0,
                "size": 100,
            },
            {
                "target": "0x00400002",
                "ui_relevant": True,
                "owner": "",
                "call_xref_count": 0,
                "size": 80,
            },
            {
                "target": "0x00400003",
                "ui_relevant": False,
                "owner": "",
                "call_xref_count": 0,
                "size": 200,
            },
        ]

        self.assertEqual(
            [row["target"] for row in sorted(rows, key=candidate_rank)],
            ["0x00400002", "0x00400001", "0x00400003"],
        )

    def test_ui_relevance_uses_target_or_registrar_identity(self) -> None:
        self.assertTrue(is_ui_relevant("OnMciNotifyMode", [], False))
        self.assertTrue(is_ui_relevant("FUN_00400000", ["TView::RegisterCallback"], False))
        self.assertTrue(is_ui_relevant("FUN_00400000", [], True))
        self.assertFalse(is_ui_relevant("CalculateProvinceYield", [], False))

    def test_committed_report_keeps_validation_controls(self) -> None:
        report = json.loads((REPO_ROOT / REPORT_PATH).read_text(encoding="utf-8"))
        validation = report["validation"]

        self.assertTrue(validation["movie_notify_handler"]["found"])
        self.assertIn("message_map", validation["movie_notify_handler"]["classification"])
        self.assertEqual(
            validation["startup_factories"]["found"],
            validation["startup_factories"]["expected"],
        )


if __name__ == "__main__":
    unittest.main()
