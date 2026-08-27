from __future__ import annotations

import unittest
from pathlib import Path

from tools.source_model import build_model
from tools.ui_codegen import (
    RUST_CITY_LAYOUT_PATH,
    RUST_UI_PATH,
    load_recipes,
    load_text_resources,
    load_ui_views,
    load_windows_views,
    render_city_building_layout,
    render_rust_ui,
    validate,
)
from tools.turn_event_vocabulary import load_turn_event_vocabulary


REPO_ROOT = Path(__file__).resolve().parents[2]


class UiCodegenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.recipes = load_recipes(REPO_ROOT)
        cls.views = load_ui_views(REPO_ROOT)
        cls.text_resources = load_text_resources(REPO_ROOT)
        cls.windows_views = load_windows_views(REPO_ROOT)
        cls.vocabulary_by_event, _ = load_turn_event_vocabulary(REPO_ROOT)

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

    def test_generated_rust_ui_is_current(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        self.assertEqual(
            rendered,
            (REPO_ROOT / RUST_UI_PATH).read_text(encoding="utf-8"),
        )

    def test_generated_city_building_layout_is_current(self) -> None:
        rendered = render_city_building_layout(REPO_ROOT)
        self.assertEqual(
            rendered,
            (REPO_ROOT / RUST_CITY_LAYOUT_PATH).read_text(encoding="utf-8"),
        )

    def test_generated_rust_ui_omits_handwritten_city_tables(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        for marker in (
            "CITY_BUILDINGS",
            "CITY_BUILDING_ACTIONS",
            "spawn_city_dialog",
            "INDUSTRY_PAGE_CONTROLS",
            "ARMORY_ROW_CONTROLS",
            "WAREHOUSE_STOCK_TAGS",
        ):
            self.assertNotIn(marker, rendered)

    def test_generated_city_layout_includes_spawn_city_dialog(self) -> None:
        rendered = render_city_building_layout(REPO_ROOT)
        self.assertIn("pub(in crate::ui::city) fn spawn_city_dialog(", rendered)
        self.assertIn("generated::citydlog_9200()", rendered)
        self.assertIn("generated::shipyard_9207()", rendered)

    def test_transport_gauge_emits_retail_helper(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        self.assertIn("retail_transport_gauge(", rendered)
        self.assertNotIn("#TransportFill", rendered)
        self.assertNotIn("TransportGaugeParts {", rendered)

    def test_transport_scene_preserves_recovered_row_controls(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        transport_scene = rendered.split("pub fn transport_2014()", 1)[1]
        fish = transport_scene[
            transport_scene.index('fourcc!("fish"), 70, 118') :
            transport_scene.index('fourcc!("fish"), 70, 118') + 1200
        ]
        for tag in ("text", "left", "rght"):
            self.assertIn(f'fourcc!("{tag}")', fish, f"fish row must keep recovered {tag}")
        self.assertIn("retail_transport_gauge(70, false)", fish)

        gold = transport_scene[
            transport_scene.index('fourcc!("gold"), 325, 304') :
            transport_scene.index('fourcc!("gold"), 325, 304') + 1600
        ]
        for tag in ("text", "left", "rght", "valu"):
            self.assertIn(f'fourcc!("{tag}")', gold, f"gold row must keep recovered {tag}")


if __name__ == "__main__":
    unittest.main()
