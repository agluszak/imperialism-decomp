#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.analysis.split_globals import ASSIGN, tu_subsystems


class TuSubsystemTests(unittest.TestCase):
    def test_uses_named_columns_and_excludes_all_tail_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            assignment = root / ASSIGN
            assignment.parent.mkdir(parents=True)
            assignment.write_text(
                "tail_uncertain|file|proposed_subsystem|n_markers|dominant_module\n"
                "0|Sampled.cpp|map|8|UMapper.cpp\n"
                "8|AllTail.cpp|ui_core|8|McAppUI.cpp\n"
                "0|Unassigned.cpp||3|Unknown.cpp\n",
                encoding="utf-8",
            )

            self.assertEqual(tu_subsystems(root), {"Sampled.cpp": "map"})


if __name__ == "__main__":
    unittest.main()
