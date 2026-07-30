"""Tests for the runtime script-debt ban.

This was a ratchet with a per-file baseline while the suite was being migrated. Every scenario is
now a linear script, so what matters is the opposite of asymmetry: any reference at all fails,
there is no count to bless, and the gate is green on a clean checkout.
"""

from __future__ import annotations

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

    def test_reports_each_mechanic_reference(self):
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
            detail = script_debt.findings_by_file(root)
            self.assertEqual(list(detail), ["tests/runtime/native/scenarios/AlphaTest.cpp"])
            self.assertEqual(len(detail["tests/runtime/native/scenarios/AlphaTest.cpp"]), 3)

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
            self.assertEqual(script_debt.findings_by_file(root), {})

    def test_a_linear_script_is_clean(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(
                root,
                {
                    "AlphaTest.cpp": (
                        "void Script() {\n"
                        "  RT_BEGIN();\n"
                        '  RT_ACTION("go", StrategicMap().EndTurn());\n'
                        "  RT_PASS();\n"
                        "  RT_END();\n"
                        "}\n"
                    )
                },
            )
            self.assertEqual(script_debt.findings_by_file(root), {})

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
            self.assertEqual(script_debt.findings_by_file(root), {})

    def test_the_ban_has_no_baseline_to_bless_a_count(self):
        """A baseline is what let a half-migrated file look like progress; there is none now."""
        self.assertFalse(hasattr(script_debt, "BASELINE_PATH"))
        self.assertFalse(hasattr(script_debt, "write_baseline"))

    def test_the_tree_is_clean(self):
        """The gate must be green on a clean checkout, or it is noise."""
        self.assertEqual(script_debt.main([]), 0)


if __name__ == "__main__":
    unittest.main()
