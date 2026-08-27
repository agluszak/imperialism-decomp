from __future__ import annotations

import unittest
from pathlib import Path

from tools.source_model import build_model
from tools.ui_codegen import (
    RUST_UI_PATH,
    load_recipes,
    load_text_resources,
    load_ui_views,
    load_windows_views,
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

    def test_transport_gauge_uses_rust_structure_helpers(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        transport = rendered[rendered.index("pub fn transport_2014()") :]
        next_fn = transport.find("\npub fn ", 1)
        if next_fn != -1:
            transport = transport[:next_fn]
        self.assertIn("transport_gauge_track_left(", transport)
        self.assertIn("transport_gauge_remainder(", transport)
        self.assertNotIn("width: px(113.", transport)
        fish = transport[transport.index('retail_node(fourcc!("fish")') :]
        fish = fish[: fish.index('retail_node(fourcc!("prod")')]
        self.assertIn("RetailSidewaysArrow", fish)
        self.assertNotIn("RetailSidewaysArrowHilite", fish)
        self.assertEqual(fish.count("Children ["), 1)

    def test_generated_sideways_arrows_use_press_repeat_not_release_button(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        trade = rendered[rendered.index("pub fn trade_2009()") : rendered.index(
            "pub fn trade_2010()"
        )]
        left = trade[
            trade.index('retail_node(fourcc!("left")') : trade.index(
                'retail_node(fourcc!("rght")'
            )
        ]
        self.assertIn("RetailSidewaysArrowHilite", left)
        self.assertNotIn("Button", left)

    def test_generated_page_corners_use_triangular_picking(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        detail = rendered[rendered.index("pub fn diplo_1352()") :]
        next_fn = detail.find("\npub fn ", 1)
        if next_fn != -1:
            detail = detail[:next_fn]
        self.assertIn("template(|_context| Ok(RetailPageCorner::Left)", detail)
        self.assertIn("template(|_context| Ok(RetailPageCorner::Right)", detail)
        lcor = detail[
            detail.index('retail_node(fourcc!("lcor")') : detail.index(
                'retail_node(fourcc!("rcor")'
            )
        ]
        self.assertIn("Button", lcor)
        self.assertIn("should_block_lower: false", lcor)


if __name__ == "__main__":
    unittest.main()
