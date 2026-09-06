from __future__ import annotations

import unittest
from pathlib import Path

from tools.ui_rust_codegen import (
    RUST_CITY_LAYOUT_OUT,
    CAPTIONED_FLOATING_WINDOW,
    CheckboxPictures,
    DEFAULT_WINDOW,
    Node,
    PictureSwap,
    PressedOverlay,
    StaticPicture,
    TextPresentation,
    _classify_picture_behavior,
    _class_lines,
    _emit_node,
    _is_captioned_floating_window,
    _require_picture,
    _require_slider,
    generate,
    is_current,
    render_city_building_layout,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _scene_source(fn_name: str) -> str:
    outputs, _ = generate(REPO_ROOT)
    marker = f"pub fn {fn_name}()"
    output = next(output for output in outputs.values() if marker in output)
    start = output.index(marker)
    next_fn = output.find("\npub fn ", start + 1)
    return output[start:] if next_fn == -1 else output[start:next_fn]


class UiRustCodegenTests(unittest.TestCase):
    def test_all_scenes_generate_without_error(self) -> None:
        outputs, scenes = generate(REPO_ROOT)
        self.assertGreater(len(scenes), 0)
        self.assertTrue(any("pub fn " in output for output in outputs.values()))
        layout = render_city_building_layout(REPO_ROOT)
        self.assertIn("CITY_BUILDINGS", layout)
        self.assertIn("CITY_BUILDING_ACTIONS", layout)

    def test_generated_output_is_current(self) -> None:
        self.assertTrue(is_current(REPO_ROOT))

    def test_picture_behavior_normalizes_class_and_catalog_evidence(self) -> None:
        pictures = {801, 1111, 4020, 4024, 4025}
        self.assertEqual(
            _classify_picture_behavior(4024, "TPictureButton", "pict", pictures),
            PressedOverlay(4024),
        )
        self.assertEqual(
            _classify_picture_behavior(4024, "T2PictureButton", "pict", pictures),
            StaticPicture(4024),
        )
        self.assertEqual(
            _classify_picture_behavior(4020, "TRightLeftView", "pict", pictures),
            StaticPicture(4020),
        )
        self.assertEqual(
            _classify_picture_behavior(1111, "TUpDownPictureButton", "pict", pictures),
            PictureSwap(1111, 1111),
        )
        self.assertEqual(
            _classify_picture_behavior(800, "TCzechBox", "chkb", pictures),
            CheckboxPictures(800, 801),
        )

    def test_armory_custom_radios_do_not_start_checked(self) -> None:
        armory = _scene_source("armory_9208")
        for tag in (f"civ{i}" for i in range(8)):
            start = armory.index(f'retail_node(fourcc!("{tag}")')
            end = armory.find("\n                                    (", start + 1)
            block = armory[start:end]
            self.assertIn("RadioButton", block)
            self.assertNotIn("Checked", block)

    def test_control_state_emits_checked_for_resource_checkboxes(self) -> None:
        node = Node(
            "0x0001", "chkb", "segu", "TCzechBox", None, (16, 32, 64, 16),
            1, 1, 1, picture_id=801, control_state=1,
        )
        lines = _class_lines(node)
        self.assertIn("Checked", lines)
        node.control_state = 0
        self.assertNotIn("Checked", _class_lines(node))

    def test_hover_help_bar_includes_recovered_presentation(self) -> None:
        startup = _scene_source("startup_1500")
        curs_start = startup.index('retail_node(fourcc!("curs")')
        curs_end = startup.index('retail_node(fourcc!("', curs_start + 1)
        block = startup[curs_start:curs_end]
        self.assertIn("hover_help_bar()", block)
        self.assertIn("retail_text_style(1, 0, 14, 1)", block)
        self.assertIn("retail_text_color(0x28)", block)
        self.assertIn("retail_text_shadow(0xd2, 1, 1)", block)

    def test_windows_created_centered_text_gets_centering(self) -> None:
        diplo = _scene_source("diplo_2008")
        self.assertIn('retail_node(fourcc!("nam0")', diplo)
        nam0_start = diplo.index('retail_node(fourcc!("nam0")')
        nam0_end = diplo.index('retail_node(fourcc!("nam1")', nam0_start)
        self.assertIn("retail_centered_text_padding(", diplo[nam0_start:nam0_end])

    def test_amount_bar_specializations(self) -> None:
        outputs, _ = generate(REPO_ROOT)
        output = "".join(outputs.values())
        self.assertIn("retail_production_amount_bar()", output)
        self.assertIn("retail_trade_amount_bar()", output)
        self.assertNotIn("retail_amount_bar(", output)

    def test_transport_gauge_specializations(self) -> None:
        transport = _scene_source("transport_2014")
        self.assertIn("{transport_capacity_gauge(325, bsn_list![", transport)
        self.assertIn("{transport_allocation_gauge(70, bsn_list![", transport)
        self.assertNotIn("transport_gauge_capacity_parts()", transport)
        self.assertNotIn("transport_gauge_allocation_parts()", transport)
        self.assertNotIn("transport_gauge_capacity_children(", transport)
        self.assertNotIn("transport_gauge_allocation_children(", transport)

    def test_transport_right_left_view_has_no_sideways_arrow_hilite(self) -> None:
        transport = _scene_source("transport_2014")
        fish_start = transport.index('retail_node(fourcc!("fish")')
        fish_end = transport.index('retail_node(fourcc!("prod")', fish_start)
        block = transport[fish_start:fish_end]
        self.assertIn("RetailSidewaysArrow", block)
        self.assertNotIn("RetailSidewaysArrowHilite", block)

    def test_missing_slider_and_picture_fail_generation(self) -> None:
        slider = Node(
            "0x0001", "pict", "slid", "TTwoPicSlider", None, (0, 0, 10, 10),
            1, 1, 1, slider=None,
        )
        placard = Node(
            "0x0002", "pict", "plac", "TPlacard", None, (0, 0, 10, 10),
            1, 1, 1, picture_id=None,
        )
        with self.assertRaises(ValueError):
            _require_slider(slider)
        with self.assertRaises(ValueError):
            _require_picture(placard)
        with self.assertRaises(ValueError):
            _class_lines(slider)
        with self.assertRaises(ValueError):
            _class_lines(placard)

    def test_edit_fields_emit_text_color(self) -> None:
        node = Node(
            "0x0003", "edit", "name", "TEditText", None, (0, 0, 100, 16),
            1, 1, 1,
            text=TextPresentation("", 1, 0, 12, 0, None, None, (0, 0), False),
            max_chars=32,
        )
        rendered = "\n".join(_emit_node(node, 4))
        self.assertIn("TextColor(Color::BLACK)", rendered)

    def test_captioned_floating_window_classification_uses_recovered_fields(self) -> None:
        node = Node(
            "0x0001", "fwnd", "WIND", "TFloatWindow", None,
            (0, 0, 320, 200), 1, 1, 1, window=CAPTIONED_FLOATING_WINDOW,
        )
        self.assertTrue(_is_captioned_floating_window(node))
        node.window = DEFAULT_WINDOW
        self.assertFalse(_is_captioned_floating_window(node))

    def test_city_layout_generated_from_evidence(self) -> None:
        layout = render_city_building_layout(REPO_ROOT)
        committed = (REPO_ROOT / RUST_CITY_LAYOUT_OUT).read_text(encoding="utf-8")
        self.assertEqual(layout, committed)
        self.assertIn("building(CityFacilitySlot::FoodProcessing, 82, 35)", layout)


if __name__ == "__main__":
    unittest.main()
