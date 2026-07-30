#!/usr/bin/env python3
"""Contracts for `just runtime-new`: every base must scaffold a test that can actually run.

The scaffold used to emit one skeleton for all bases, so a generated `managers-ready` test
waited for a screen its base never creates, and a generated `loaded-map` test carried no
fixture although its base refuses to run without one. Both produced a file that compiled and
then stalled, which is the worst failure mode a scaffold has. These tests are table-driven over
every base for that reason: a new base with no entry here fails `test_every_base_is_covered`.
"""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.runtime import scaffold
from tools.runtime.scaffold import BASES


# Identifiers the runtime-script-debt gate hard-bans inside a scenario body. A skeleton that
# emitted one would hand every new test a gate failure on its first commit.
BANNED_IN_SCENARIOS = (
    "g_ModalViewStack",
    "ResolveControlByTag",
    "RUNTIME_CLASS",
    "RuntimeUiDriver",
    "EnterScenarioStep",
    "ContinueAfterAction",
)

CATALOG_STUB = '''"""Stub catalog."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeFixtureSpec:
    filename: str
    evidence_kind: str
    provenance_required: bool = True


@dataclass(frozen=True)
class RuntimeTestSpec:
    name: str
    native_factory: str
    suites: tuple
    evidence_kind: str
    fixture: object = None
    required_oracles: tuple = ("ui",)


TESTS = (
    RuntimeTestSpec(
        "already_present",
        "AlreadyPresentTest",
        ("full",),
        "internal_invariant",
        required_oracles=(),
    ),
)
'''


class ScaffoldBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        (self.repo / "tools" / "runtime").mkdir(parents=True)
        (self.repo / "tools" / "runtime" / "catalog.py").write_text(CATALOG_STUB, encoding="utf-8")
        (self.repo / "tests" / "runtime" / "native" / "scenarios").mkdir(parents=True)
        (self.repo / "tests" / "runtime" / "fixtures").mkdir(parents=True)
        self.addCleanup(self._tmp.cleanup)

    def run_scaffold(self, *argv: str) -> int:
        with patch.object(scaffold, "repo_root_from_file", return_value=self.repo), patch.object(
            scaffold, "TESTS", ()
        ):
            return scaffold.main(list(argv))

    def source_for(self, factory: str) -> str:
        path = self.repo / "tests" / "runtime" / "native" / "scenarios" / f"{factory}.cpp"
        self.assertTrue(path.is_file(), f"{factory}.cpp was not written")
        return path.read_text(encoding="utf-8")

    def catalog_text(self) -> str:
        return (self.repo / "tools" / "runtime" / "catalog.py").read_text(encoding="utf-8")

    def test_every_base_is_covered(self) -> None:
        """A base added to BASES without a case here is an untested code path."""
        self.assertEqual(
            set(BASES),
            {"easy-map", "introductory-map", "combined-map", "loaded-map", "managers-ready"},
        )

    def test_each_base_scaffolds_its_own_scenario_class(self) -> None:
        for name, spec in sorted(BASES.items()):
            with self.subTest(base=name):
                extra = ["--fixture", "beginning_of_game.imp"] if spec.requires_fixture else []
                self.assertEqual(0, self.run_scaffold(f"t_{name.replace('-', '_')}",
                                                      "--base", name, *extra))
                source = self.source_for(f"T{name.title().replace('-', '')}Test")
                self.assertIn(f"public {spec.scenario_class}", source)
                self.assertIn("void Script() override", source)
                self.assertIn("RT_BEGIN();", source)
                self.assertIn("RT_PASS();", source)
                self.assertIn("RT_END();", source)

    def test_no_base_waits_for_a_screen_its_base_already_reached(self) -> None:
        """Every base hands over past its checkpoint, so no skeleton should re-await it."""
        for name, spec in sorted(BASES.items()):
            with self.subTest(base=name):
                extra = ["--fixture", "beginning_of_game.imp"] if spec.requires_fixture else []
                self.run_scaffold(f"w_{name.replace('-', '_')}", "--base", name, *extra)
                source = self.source_for(f"W{name.title().replace('-', '')}Test")
                self.assertNotIn("RT_AWAIT_SCREEN", source)

    def test_managers_ready_pulls_in_no_screen(self) -> None:
        """It has no main window, so a screen include is at best noise and at worst a stall."""
        self.run_scaffold("model_only", "--base", "managers-ready")
        source = self.source_for("ModelOnlyTest")
        self.assertNotIn("screens/", source)
        self.assertNotIn("TMapUberPicture", source)
        self.assertNotIn("kTurnEventStrategicMap", source)

    def test_map_bases_offer_the_strategic_map_screen(self) -> None:
        for name in ("easy-map", "introductory-map", "combined-map", "loaded-map"):
            with self.subTest(base=name):
                extra = (
                    ["--fixture", "beginning_of_game.imp"] if name == "loaded-map" else []
                )
                self.run_scaffold(f"m_{name.replace('-', '_')}", "--base", name, *extra)
                source = self.source_for(f"M{name.title().replace('-', '')}Test")
                self.assertIn('#include "screens/StrategicMapScreen.h"', source)

    def test_no_skeleton_trips_the_script_debt_gate(self) -> None:
        for name, spec in sorted(BASES.items()):
            with self.subTest(base=name):
                extra = ["--fixture", "beginning_of_game.imp"] if spec.requires_fixture else []
                self.run_scaffold(f"d_{name.replace('-', '_')}", "--base", name, *extra)
                source = self.source_for(f"D{name.title().replace('-', '')}Test")
                for banned in BANNED_IN_SCENARIOS:
                    self.assertNotIn(banned, source)


class ScaffoldFixtureTests(ScaffoldBaseTests):
    def test_loaded_map_without_a_fixture_is_refused(self) -> None:
        """LoadedMapScriptScenario enforces fixture presence, so this test could never run."""
        self.assertEqual(2, self.run_scaffold("needs_a_save", "--base", "loaded-map"))
        self.assertFalse(
            (self.repo / "tests" / "runtime" / "native" / "scenarios" / "NeedsASaveTest.cpp").exists()
        )
        self.assertNotIn("needs_a_save", self.catalog_text())

    def test_fixture_on_a_base_that_never_loads_one_is_refused(self) -> None:
        self.assertEqual(
            2,
            self.run_scaffold(
                "no_load_here", "--base", "easy-map", "--fixture", "beginning_of_game.imp"
            ),
        )

    def test_loaded_map_emits_a_fixture_spec_and_retail_evidence(self) -> None:
        self.assertEqual(
            0,
            self.run_scaffold(
                "replays_a_save", "--base", "loaded-map", "--fixture", "beginning_of_game.imp"
            ),
        )
        catalog = self.catalog_text()
        self.assertIn('fixture=RuntimeFixtureSpec(\n            "beginning_of_game.imp"', catalog)
        self.assertIn('"retail_fixture_oracle"', catalog)
        # The entry must still be valid Python, and still one TESTS tuple.
        ast.parse(catalog)

    def test_missing_fixture_file_warns_but_still_scaffolds(self) -> None:
        """Writing the test before producing its save is a reasonable order to work in."""
        self.assertEqual(
            0,
            self.run_scaffold("save_not_made_yet", "--base", "loaded-map", "--fixture", "later.imp"),
        )
        self.assertIn("later.imp", self.catalog_text())

    def test_non_fixture_base_keeps_internal_invariant_evidence(self) -> None:
        self.run_scaffold("plain_one", "--base", "easy-map")
        self.assertIn('"internal_invariant"', self.catalog_text())
        # The stub defines the class, so look for the keyword that only a generated entry emits.
        self.assertNotIn("fixture=RuntimeFixtureSpec", self.catalog_text())


if __name__ == "__main__":
    unittest.main()
