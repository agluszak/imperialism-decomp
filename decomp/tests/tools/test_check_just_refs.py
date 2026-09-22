from __future__ import annotations

from pathlib import Path
import unittest

from tools.workflow.check_just_refs import cited_recipe, main, recipe_names


REPO_ROOT = Path(__file__).resolve().parents[2]


class CitedRecipeTests(unittest.TestCase):
    def test_plain_recipe(self) -> None:
        self.assertEqual(cited_recipe("build"), "build")

    def test_recipe_with_args(self) -> None:
        self.assertEqual(cited_recipe("compare 0xADDR"), "compare")
        self.assertEqual(cited_recipe("ghidra listing 0xADDR"), "ghidra")

    def test_variable_overrides_skip_to_recipe(self) -> None:
        self.assertEqual(
            cited_recipe("build_dir=X cmake_flags=... _build-msvc500-unlocked"),
            "_build-msvc500-unlocked",
        )

    def test_flag_only_span_has_no_recipe(self) -> None:
        self.assertIsNone(cited_recipe("--list"))


class RecipeNameParseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.recipes = recipe_names(REPO_ROOT)

    def test_public_and_private_recipes_parse(self) -> None:
        for name in ("build", "noop-audit", "ghidra-daemon", "precommit"):
            self.assertIn(name, self.recipes)

    def test_assignments_and_attributes_are_not_recipes(self) -> None:
        for name in ("build_dir", "docker_image", "target"):
            self.assertNotIn(name, self.recipes)


class GateWholeTreeTests(unittest.TestCase):
    def test_gate_passes_on_committed_tree(self) -> None:
        self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
