from __future__ import annotations

import unittest
from pathlib import Path

from tools.ui_rust_codegen import (
    RUST_CITY_LAYOUT_OUT,
    RUST_OUT,
    Node,
    TextPresentation,
    _class_lines,
    _emit_node,
    _require_picture,
    _require_slider,
    generate,
    is_current,
    render_city_building_layout,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _scene_source(fn_name: str) -> str:
    output, _ = generate(REPO_ROOT)
    marker = f"pub fn {fn_name}()"
    start = output.index(marker)
    next_fn = output.find("\npub fn ", start + 1)
    return output[start:] if next_fn == -1 else output[start:next_fn]


class UiRustCodegenTests(unittest.TestCase):
    def test_all_scenes_generate_without_error(self) -> None:
        output, scenes = generate(REPO_ROOT)
        self.assertGreater(len(scenes), 0)
        self.assertIn("pub fn ", output)
        layout = render_city_building_layout(REPO_ROOT)
        self.assertIn("CITY_BUILDINGS", layout)
        self.assertIn("CITY_BUILDING_ACTIONS", layout)

    def test_generated_output_is_current(self) -> None:
        self.assertTrue(is_current(REPO_ROOT))

    def test_newspaper_buttons_do_not_assume_missing_pressed_art(self) -> None:
        newspaper = _scene_source("flagview_8451")
        self.assertIn("retail_picture(8454)", newspaper)
        self.assertIn("retail_picture(8456)", newspaper)
        self.assertNotIn("InteractionDisabled", newspaper)
        self.assertNotIn("retail_picture_button(8454", newspaper)
        self.assertNotIn("retail_picture_button(8456", newspaper)

    def test_picture_button_does_not_pair_the_transport_return_with_query_art(self) -> None:
        transport = _scene_source("transport_2014")
        return_start = transport.index('retail_node(fourcc!("end ")')
        return_end = transport.index('retail_node(fourcc!("seas")', return_start)
        return_button = transport[return_start:return_end]
        self.assertIn("retail_picture(4024)", return_button)
        self.assertNotIn("retail_picture_button", return_button)

    def test_strategic_transport_button_does_not_assume_missing_active_art(self) -> None:
        strategic_map = _scene_source("mapview_2013")
        self.assertIn("retail_picture_swap(1111, 1111)", strategic_map)
        self.assertNotIn("retail_picture_swap(1111, 1112)", strategic_map)

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
        output, _ = generate(REPO_ROOT)
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

    def test_page_corner_emits_marker_components(self) -> None:
        output, _ = generate(REPO_ROOT)
        self.assertIn("RetailPageCornerLeft", output)
        self.assertIn("RetailPageCornerRight", output)
        self.assertNotIn("retail_page_corner_left()", output)
        self.assertNotIn("retail_page_corner_right()", output)

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

    def test_floating_captioned_windows_emit_without_retail_view_wrapper(self) -> None:
        for fn_name in ("linger_3000", "citydlog_9200", "citydlog_9201"):
            source = _scene_source(fn_name)
            self.assertNotIn("retail_view(", source, fn_name)
            self.assertIn("captioned_window(bsn_list![", source, fn_name)
            self.assertNotIn("captioned_window()\n", source, fn_name)

    def test_non_captioned_window_scenes_stay_wrapped_in_retail_view(self) -> None:
        for fn_name in ("startup_1500", "transport_2014", "mapview_2013", "citydlog_9220", "linger_2020"):
            source = _scene_source(fn_name)
            self.assertIn("retail_view(", source, fn_name)

    def test_city_layout_generated_from_evidence(self) -> None:
        layout = render_city_building_layout(REPO_ROOT)
        committed = (REPO_ROOT / RUST_CITY_LAYOUT_OUT).read_text(encoding="utf-8")
        self.assertEqual(layout, committed)
        self.assertIn("building(CityFacilitySlot::FoodProcessing, 82, 35)", layout)


if __name__ == "__main__":
    unittest.main()
