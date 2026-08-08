"""Tests for the ILT/thunk-name ossification detection."""

from __future__ import annotations

import unittest

from tools.workflow.check_ilt_ossification import is_ossified, strip_line_comment


class TestIsOssified(unittest.TestCase):
    def test_thunk_and_ilt_prefixes_flagged(self):
        self.assertTrue(is_ossified("thunk_Foo"))
        self.assertTrue(is_ossified("ILT_Foo"))
        self.assertTrue(is_ossified("thunk_WrapperFor_Bar_At004f6d90"))

    def test_wrapperfor_prefix_flagged(self):
        self.assertTrue(is_ossified("WrapperFor_InvalidateCityDialogRectRegion_At004f6d90"))
        self.assertTrue(is_ossified("WrapperFor_thunk_SetGlobalUiInvalidationFlag_At0049d900"))

    def test_at_hex_suffix_flagged(self):
        self.assertTrue(is_ossified("Function_At0049d900"))
        self.assertTrue(is_ossified("IsPointInsideHitRegion_At0050d6c0"))

    def test_clean_names_not_flagged(self):
        self.assertFalse(is_ossified("TemporarilyClearAndRestoreUiInvalidationFlag"))
        self.assertFalse(is_ossified("AdornerSlot28"))
        self.assertFalse(is_ossified("RefreshMainDialogAfterPaletteChange"))
        # Near-misses that must NOT trip the suffix rule.
        self.assertFalse(is_ossified("field_At"))  # no 8 hex digits
        self.assertFalse(is_ossified("SlotAt12"))  # not the _At<hex> shape
        self.assertFalse(is_ossified("_At0049d90"))  # only 7 hex digits


class TestStripLineComment(unittest.TestCase):
    def test_full_line_comment_removed(self):
        self.assertEqual(strip_line_comment("  // slot 0x71 WrapperFor_X_At0049d900").strip(), "")

    def test_trailing_comment_removed_keeps_code(self):
        code = strip_line_comment("  Foo();  // WrapperFor_X_At0049d900 old name")
        self.assertIn("Foo();", code)
        self.assertNotIn("WrapperFor_X", code)

    def test_code_before_comment_still_scanned(self):
        code = strip_line_comment("  reinterpret_cast<T>(thunk_Foo)(1); // real call")
        idents = [t for t in code.replace("(", " ").replace(")", " ").split() if is_ossified(t)]
        self.assertIn("thunk_Foo", " ".join(idents))


if __name__ == "__main__":
    unittest.main()
