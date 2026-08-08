from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.runtime.source_policy import check_paths


class RuntimeSourcePolicyTests(unittest.TestCase):
    def check_source(self, source: str, *, scenario: bool = False) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if scenario:
                path = root / "scenarios" / "ScenarioTest.cpp"
                path.parent.mkdir()
            else:
                path = root / "Scenario.cpp"
            path.write_text(source, encoding="utf-8")
            return [finding.rule for finding in check_paths([path if not scenario else root])]

    def test_rejects_coordinate_input_and_polling(self) -> None:
        rules = self.check_source(
            "SendMessageA(hwnd, WM_LBUTTONDOWN, 0, 0);\n"
            "RequestScenarioTick();\n"
            "QueueControlClickThroughNativeMessages(root, tag);\n"
        )
        self.assertEqual(
            rules,
            [
                "mouse button message",
                "scenario tick request",
                "coordinate control activation",
            ],
        )

    def test_rejects_unexplained_literal_points(self) -> None:
        self.assertEqual(
            self.check_source("CPoint clickPoint(12, 0x20);\n"),
            ["unexplained literal point"],
        )

    def test_accepts_semantic_actions_and_explained_geometry(self) -> None:
        self.assertEqual(
            self.check_source(
                "driver.ActivateNation(targetNation);\n"
                "CPoint bitmapOrigin(0, 0); // RUNTIME_COORDINATE_EXPLAINED: bitmap origin\n"
            ),
            [],
        )

    def test_scenario_body_rejects_control_tree_mechanics(self) -> None:
        rules = self.check_source(
            "auto* view = ResolveControlByTag(root, tag);\n"
            "BitBlt(hdc, 0, 0, 1, 1, src, 0, 0, SRCCOPY);\n"
            "auto top = g_ModalViewStack;\n",
            scenario=True,
        )
        self.assertEqual(
            rules,
            ["tag resolution", "gdi surface", "modal stack"],
        )

    def test_non_scenario_may_use_control_tree_helpers(self) -> None:
        self.assertEqual(
            self.check_source("ResolveControlByTag(root, tag);\nBitBlt(hdc, 0, 0, 1, 1, src, 0, 0, SRCCOPY);\n"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
