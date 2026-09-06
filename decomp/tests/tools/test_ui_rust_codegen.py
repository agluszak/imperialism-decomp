from __future__ import annotations

import unittest
from pathlib import Path

from tools.ui_rust_codegen import (
    CAPTIONED_FLOATING_WINDOW,
    CheckboxPictures,
    DEFAULT_WINDOW,
    Node,
    PictureSwap,
    PressedOverlay,
    StaticPicture,
    _classify_picture_behavior,
    _is_captioned_floating_window,
    _require_picture,
    _require_slider,
    is_current,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class UiRustCodegenTests(unittest.TestCase):
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

    def test_captioned_floating_window_classification_uses_recovered_fields(self) -> None:
        node = Node(
            "0x0001", "fwnd", "WIND", "TFloatWindow", None,
            (0, 0, 320, 200), 1, 1, 1, window=CAPTIONED_FLOATING_WINDOW,
        )
        self.assertTrue(_is_captioned_floating_window(node))
        node.window = DEFAULT_WINDOW
        self.assertFalse(_is_captioned_floating_window(node))


if __name__ == "__main__":
    unittest.main()
