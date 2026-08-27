from __future__ import annotations

import unittest
from pathlib import Path

from tools.source_model import build_model
from tools.ui_codegen import (
    RUST_CITY_LAYOUT_PATH,
    RUST_UI_PATH,
    WidgetKind,
    _case_for_resource,
    apply_case_windows_overrides,
    apply_two_pic_slider_instances,
    apply_windows_child_node_patches,
    apply_windows_text_property_patches,
    classify_widget,
    load_class_substitutions,
    load_recipes,
    load_text_resources,
    load_two_pic_slider_instances,
    load_ui_views,
    load_windows_child_node_patches,
    load_windows_text_property_patches,
    load_windows_views,
    normalize_resource_view,
    render_city_building_layout,
    render_rust_ui,
    resource_backed_scene_keys,
    validate,
)
from tools.turn_event_vocabulary import load_turn_event_vocabulary


REPO_ROOT = Path(__file__).resolve().parents[2]


def _iter_rust_semantic_nodes(repo_root: Path):
    recipes = load_recipes(repo_root)
    views = load_ui_views(repo_root)
    text_resources = load_text_resources(repo_root)
    text_property_patches = load_windows_text_property_patches(repo_root)
    child_node_patches = load_windows_child_node_patches(repo_root)
    two_pic_sliders = load_two_pic_slider_instances(repo_root)
    windows_views = load_windows_views(repo_root)

    class_substitutions = load_class_substitutions(repo_root)
    for key in resource_backed_scene_keys(recipes):
        raw_view = views[key]
        recipe, case = _case_for_resource(recipes, key)
        semantic_view = normalize_resource_view(
            key, raw_view, text_resources, class_substitutions
        )
        semantic_view = apply_case_windows_overrides(recipe, case, semantic_view)
        semantic_view = apply_windows_text_property_patches(
            key, semantic_view, text_property_patches, text_resources
        )
        semantic_view = apply_windows_child_node_patches(
            key, semantic_view, child_node_patches
        )
        semantic_view = apply_two_pic_slider_instances(
            key, semantic_view, two_pic_sliders
        )
        for node in semantic_view.nodes:
            yield key, node

    for view_name, semantic_view in windows_views.items():
        for node in semantic_view.nodes:
            yield view_name, node


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

    def test_transport_gauge_emits_retail_helper(self) -> None:
        rendered = render_rust_ui(
            REPO_ROOT, self.recipes, self.views, self.text_resources
        )
        self.assertIn("retail_transport_gauge(", rendered)
        self.assertNotIn("#TransportFill", rendered)
        self.assertNotIn("TransportGaugeParts {", rendered)


class WidgetClassificationTests(unittest.TestCase):
    def test_all_recovered_nodes_classify(self) -> None:
        for key, node in _iter_rust_semantic_nodes(REPO_ROOT):
            spec = classify_widget(key, node)
            self.assertIsInstance(spec.kind, WidgetKind)

    def test_known_widget_kinds(self) -> None:
        cases = {
            ("TCzechBox", "pict"): WidgetKind.CHECKBOX,
            ("TTwoPicSlider", "cntl"): WidgetKind.TWO_PIC_SLIDER,
            ("TTransportPicture", "pict"): WidgetKind.TRANSPORT_GAUGE,
            ("TRadioTextCluster", "clus"): WidgetKind.RADIO_GROUP,
            ("TNumberedArrowButton", "cntl"): WidgetKind.NUMBERED_ARROW,
            ("TIndustryAmtBar", "view"): WidgetKind.AMOUNT_BAR,
            ("TPictureButton", "pict"): WidgetKind.PRESSED_OVERLAY,
            ("TUpDownPictureButton", "pict"): WidgetKind.PICTURE_SWAP,
            ("TRadioText", "stat"): WidgetKind.RADIO_TEXT_FILL,
            ("TInfoBarText", "tevw"): WidgetKind.HOVER_HELP_BAR,
        }
        for (class_name, type_code), expected in cases.items():
            for key, node in _iter_rust_semantic_nodes(REPO_ROOT):
                if node.class_name == class_name and node.type_code == type_code:
                    self.assertEqual(classify_widget(key, node).kind, expected)
                    break
            else:
                self.fail(f"no recovered node for {class_name}/{type_code}")

    def test_amount_bar_styles(self) -> None:
        expected = {
            "TIndustryAmtBar": "Production",
            "TRailAmtBar": "Production",
            "TTraderAmtBar": "Trade",
        }
        for class_name, style in expected.items():
            for key, node in _iter_rust_semantic_nodes(REPO_ROOT):
                if node.class_name == class_name:
                    spec = classify_widget(key, node)
                    self.assertEqual(spec.kind, WidgetKind.AMOUNT_BAR)
                    self.assertEqual(spec.amount_bar_style, style)
                    break
            else:
                self.fail(f"no recovered node for {class_name}")


if __name__ == "__main__":
    unittest.main()
