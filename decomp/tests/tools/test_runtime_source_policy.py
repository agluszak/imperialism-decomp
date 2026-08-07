from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.runtime.source_policy import check_paths


class RuntimeSourcePolicyTests(unittest.TestCase):
    def check_source(self, source: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Scenario.cpp"
            path.write_text(source, encoding="utf-8")
            return [finding.rule for finding in check_paths([path])]

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
