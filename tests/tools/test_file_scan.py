#!/usr/bin/env python3
"""Tests for shared source-file scanning helpers."""

from __future__ import annotations

import unittest

from tools.common.file_scan import strip_generated_blocks


class GeneratedBlockStripTests(unittest.TestCase):
    def test_strips_generated_block_but_keeps_hand_content(self) -> None:
        text = "\n".join(
            [
                "int keep_before();",
                "// === BEGIN GENERATED (TFoo) - refreshed by `just gen-class TFoo`; do not hand-edit ===",
                "// raw provisional WrapperFor_SlotNameAndMaybeFree",
                "// === END GENERATED (TFoo) ===",
                "int keep_after();",
            ]
        )

        stripped = strip_generated_blocks(text)

        self.assertIn("int keep_before();", stripped)
        self.assertIn("int keep_after();", stripped)
        self.assertNotIn("WrapperFor_SlotNameAndMaybeFree", stripped)
        self.assertEqual(len(text.splitlines()), len(stripped.splitlines()))


if __name__ == "__main__":
    unittest.main()
