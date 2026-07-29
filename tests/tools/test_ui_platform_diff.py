from __future__ import annotations

from pathlib import Path
import unittest

from tools.workflow.ui_platform_diff import build_report


REPO_ROOT = Path(__file__).resolve().parents[2]


class UiPlatformDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report, cls.errors = build_report(REPO_ROOT)

    def test_report_covers_every_generated_case_and_node(self) -> None:
        self.assertEqual(self.errors, [])
        self.assertEqual(self.report["summary"]["functions"], 17)
        self.assertEqual(self.report["summary"]["cases"], 94)
        self.assertEqual(self.report["summary"]["nodes"], 1853)
        self.assertEqual(self.report["summary"]["unexplained_deltas"], 0)

    def test_declared_toolbar_class_substitution_is_explicit(self) -> None:
        node = self.report["functions"]["0x00430c50"]["cases"]["0x2260"]["nodes"][
            "0x06f3"
        ]

        self.assertEqual(node["classification"], "expected_windows_class_substitution")
        self.assertEqual(node["delta"]["mac"], "TToolbarCluster")
        self.assertEqual(node["delta"]["windows"], "TToolBarCluster")
        self.assertIsNotNone(node["generated_lines"])

    def test_windows_only_case_retains_per_node_binary_evidence(self) -> None:
        case = self.report["functions"]["0x0044af90"]["cases"]["0x05e7"]

        self.assertEqual(case["classification"], "windows_only")
        self.assertEqual(len(case["nodes"]), 12)
        self.assertTrue(
            all(
                node["windows_binary_evidence"].startswith("Windows evidence at 0x")
                for node in case["nodes"].values()
            )
        )

    def test_functional_parity_extensions_are_distinct_from_platform_nodes(self) -> None:
        case = self.report["functions"]["0x004357b0"]["cases"]["0x07e5"]

        self.assertEqual(case["classification"], "functional_parity_extension")
        self.assertIn("0x005d57ce", case["manifest_evidence"])


if __name__ == "__main__":
    unittest.main()
