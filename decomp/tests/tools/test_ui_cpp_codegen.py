from __future__ import annotations

import unittest
from pathlib import Path

from tools.source_model import build_model
from tools.ui_cpp_codegen import (
    load_recipes,
    load_text_resources,
    load_ui_views,
    load_windows_views,
    validate,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class UiCppCodegenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.recipes = load_recipes(REPO_ROOT)
        cls.views = load_ui_views(REPO_ROOT)
        cls.text_resources = load_text_resources(REPO_ROOT)
        cls.windows_views = load_windows_views(REPO_ROOT)

    def test_committed_manifest_and_resource_ir_validate(self) -> None:
        self.assertEqual(len(self.recipes), 17)
        self.assertEqual(sum(len(recipe.cases) for recipe in self.recipes), 82)
        self.assertEqual(
            validate(
                REPO_ROOT,
                self.recipes,
                self.views,
                self.text_resources,
                self.windows_views,
            ),
            [],
        )

    def test_generated_claims_replace_manual_factory_ownership(self) -> None:
        model = build_model(REPO_ROOT)
        for recipe in self.recipes:
            claim = model.functions[recipe.address]
            self.assertEqual(claim.origin, "generated")
            self.assertNotIn(recipe.address, model.duplicates)


if __name__ == "__main__":
    unittest.main()
