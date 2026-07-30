"""Tests for the runtime script-debt ratchet.

The behaviour that matters is asymmetry: a falling count is recorded without ceremony, while a
rising count or a newly-offending scenario fails. A symmetric gate would let a half-migrated
file look like progress, and a hard ban would be unlandable while ten scenarios still use the
old shape.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.runtime import script_debt


class ScriptDebtTest(unittest.TestCase):
    def _repo(self, root: Path, files: dict[str, str]) -> None:
        scenarios = root / script_debt.SCENARIO_DIR
        scenarios.mkdir(parents=True, exist_ok=True)
        for name, body in files.items():
            (scenarios / name).write_text(body, encoding="utf-8")

    def test_counts_each_mechanic_reference(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(
                root,
                {
                    "AlphaTest.cpp": (
                        "void Advance() {\n"
                        "  if (!g_ModalViewStack.IsEmpty()) {}\n"
                        "  TView* v = CurrentMainView();\n"
                        "  v->ResolveControlByTag(1);\n"
                        "}\n"
                    )
                },
            )
            counts, _ = script_debt.counts_by_file(root)
            self.assertEqual(counts, {"tests/runtime/native/scenarios/AlphaTest.cpp": 3})

    def test_a_comment_naming_a_mechanic_is_not_a_use(self):
        """The skill and the migrated tests discuss these identifiers in prose."""
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(
                root,
                {
                    "AlphaTest.cpp": (
                        "// ResolveControlByTag and g_ModalViewStack belong in a screen.\n"
                        "void Script() {}\n"
                    )
                },
            )
            counts, _ = script_debt.counts_by_file(root)
            self.assertEqual(counts, {})

    def test_a_migrated_scenario_has_no_entry(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(
                root,
                {
                    "AlphaTest.cpp": (
                        "void Script() {\n"
                        "  RT_BEGIN();\n"
                        "  RT_ACTION(\"go\", StrategicMap().EndTurn());\n"
                        "  RT_PASS();\n"
                        "  RT_END();\n"
                        "}\n"
                    )
                },
            )
            counts, _ = script_debt.counts_by_file(root)
            self.assertEqual(counts, {})

    def test_only_test_files_are_scanned(self):
        """The scenario base and its helpers legitimately use every one of these."""
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(
                root,
                {
                    "RuntimeScenario.cpp": "void f() { CurrentMainView(); }\n",
                    "AlphaTest.cpp": "void Script() {}\n",
                },
            )
            counts, _ = script_debt.counts_by_file(root)
            self.assertEqual(counts, {})

    def _write_baseline(self, root: Path, debt: dict[str, int]) -> None:
        path = root / script_debt.BASELINE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"debt": debt}), encoding="utf-8")

    def test_baseline_roundtrips(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            script_debt.write_baseline(root, {"a": 2, "b": 1})
            self.assertEqual(script_debt.load_baseline(root), {"a": 2, "b": 1})

    def test_missing_baseline_reads_as_empty(self):
        with TemporaryDirectory() as raw:
            self.assertEqual(script_debt.load_baseline(Path(raw)), {})

    def test_written_baseline_records_the_total(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            script_debt.write_baseline(root, {"a": 2, "b": 3})
            data = json.loads((root / script_debt.BASELINE_PATH).read_text(encoding="utf-8"))
            self.assertEqual(data["total"], 5)
            # Sorted so a diff of the baseline is reviewable.
            self.assertEqual(list(data["debt"]), ["a", "b"])

    def test_committed_baseline_matches_the_tree(self):
        """The gate must be green on a clean checkout, or it is noise."""
        self.assertEqual(script_debt.main([]), 0)


if __name__ == "__main__":
    unittest.main()
