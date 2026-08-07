#!/usr/bin/env python3
"""Tests for verified vtable extent collision handling."""

from __future__ import annotations

import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

from tools.common.vtable_extents import (
    containing_vtable_extent,
    load_verified_vtable_extents,
)


class VtableExtentTests(unittest.TestCase):
    def test_finds_only_strictly_interior_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "extents.csv"
            path.write_text(
                "address|slots|class|evidence\n"
                "1000|3|TExample|unit_test\n",
                encoding="utf-8",
            )
            extents = load_verified_vtable_extents(path)

        self.assertIsNone(containing_vtable_extent(0x1000, extents))
        self.assertEqual(containing_vtable_extent(0x1004, extents).class_name, "TExample")
        self.assertEqual(containing_vtable_extent(0x1008, extents).class_name, "TExample")
        self.assertIsNone(containing_vtable_extent(0x100C, extents))

    def test_rejects_invalid_extent_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "extents.csv"
            path.write_text(
                "address|slots|class|evidence\n1000|0|TExample|unit_test\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_verified_vtable_extents(path)

    def test_gate_rejects_inventory_entity_inside_verified_extent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            include = root / "include"
            include.mkdir()
            (include / "TExample.h").write_text(
                "// VTABLE: IMPERIALISM 0x1000\nclass TExample {};\n",
                encoding="utf-8",
            )
            symbols = root / "original_entities.csv"
            symbols.write_text(
                "address|name|symbol|size|type|prototype|provenance\n"
                "1004|StaleBoundary|||global||\n",
                encoding="utf-8",
            )
            extents = root / "extents.csv"
            extents.write_text(
                "address|slots|class|evidence\n1000|3|TExample|unit_test\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.workflow.check_vtable_address_collisions",
                    "--paths",
                    str(include),
                    "--symbols-csv",
                    str(symbols),
                    "--verified-extents",
                    str(extents),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("lies inside TExample's verified vtable range", result.stdout)


if __name__ == "__main__":
    unittest.main()
