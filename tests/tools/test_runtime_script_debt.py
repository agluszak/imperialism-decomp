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
from tools.runtime.script_debt import scan_file


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


class Win32MechanicsTests(unittest.TestCase):
    """The GDI/input half of the ban: a scenario that renders or synthesises input itself.

    The identifier ban could not see these. A scenario that never writes ResolveControlByTag but
    does CreateDIBSection/BitBlt on a view, or posts its own WM_MOUSEMOVE, is reaching through the
    boundary just as directly -- past a different part of it.
    """

    def _scan(self, source: str):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            scenarios = root / "tests" / "runtime" / "native" / "scenarios"
            scenarios.mkdir(parents=True)
            path = scenarios / "ProbeTest.cpp"
            path.write_text(source, encoding="utf-8")
            return scan_file(path, root)

    def test_gdi_capture_is_rejected(self):
        findings = self._scan('HBITMAP b = CreateDIBSection(dc, &info, 0, &bits, 0, 0);\n')
        self.assertEqual(["gdi surface"], [f.rule for f in findings])

    def test_blit_is_rejected(self):
        self.assertTrue(self._scan("BitBlt(dst, 0, 0, w, h, src, 0, 0, SRCCOPY);\n"))

    def test_synthesised_input_is_rejected(self):
        findings = self._scan("SendMessageA(host, WM_MOUSEMOVE, 0, MAKELPARAM(x, y));\n")
        self.assertEqual(["synthesised input"], [f.rule for f in findings])

    def test_quickdraw_surface_switching_is_rejected(self):
        findings = self._scan("SetGWorld(surface, flags);\n")
        self.assertEqual(["quickdraw surface"], [f.rule for f in findings])

    def test_cursor_state_is_rejected(self):
        self.assertTrue(self._scan("if (GetCursor() != expected) { return false; }\n"))

    def test_model_assertions_are_untouched(self):
        """The gate must not push scenarios away from asserting on the game's own state."""
        self.assertEqual([], self._scan(
            'RT_REQUIRE_EQ(3, g_pSimMgr->GetActiveNationId());\n'
            'RT_REQUIRE(Player()->GetTradeOffersFor(kResourceIron) == -1);\n'))

    def test_a_comment_naming_a_mechanic_is_documentation(self):
        self.assertEqual([], self._scan("// BitBlt lives in MapRenderingProbe, not here.\n"))
