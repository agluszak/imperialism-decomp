"""Coverage for ASSERT_SIZE collection in the class-size gate."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from tools.workflow.check_class_sizes import collect_asserts


class CollectAssertsTests(unittest.TestCase):
    def test_finds_hex_and_decimal_asserts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "include").mkdir()
            (root / "include" / "TThing.h").write_text(
                "ASSERT_SIZE(TThing, 0x40);\n", encoding="utf-8"
            )
            (root / "src").mkdir()
            (root / "src" / "TOther.cpp").write_text(
                "ASSERT_SIZE(TOther, 32);\n", encoding="utf-8"
            )
            found = collect_asserts(root)
            self.assertEqual(found["TThing"][0], 0x40)
            self.assertEqual(found["TOther"][0], 32)

    def test_generated_trees_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gen = root / "src" / "autogen"
            gen.mkdir(parents=True)
            (gen / "gen.cpp").write_text(
                "ASSERT_SIZE(TGenerated, 0x10);\n", encoding="utf-8"
            )
            self.assertNotIn("TGenerated", collect_asserts(root))

    def test_no_asserts_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "include").mkdir()
            (root / "include" / "TThing.h").write_text(
                "class TThing {};\n", encoding="utf-8"
            )
            self.assertEqual(collect_asserts(root), {})


if __name__ == "__main__":
    unittest.main()
