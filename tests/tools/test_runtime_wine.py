#!/usr/bin/env python3
"""Contracts for immutable seeded Wine-prefix templates."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime import wine


class WinePrefixTemplateTests(unittest.TestCase):
    def test_identity_changes_with_schema_or_seeded_registry(self) -> None:
        baseline = wine.template_identity("wine-10.0")
        with patch.object(wine, "PREFIX_TEMPLATE_SCHEMA", wine.PREFIX_TEMPLATE_SCHEMA + 1):
            self.assertNotEqual(wine.template_identity("wine-10.0"), baseline)
        with patch.object(
            wine,
            "SEEDED_REGISTRY_VALUES",
            wine.SEEDED_REGISTRY_VALUES + (("Extra", None, "1"),),
        ):
            self.assertNotEqual(wine.template_identity("wine-10.0"), baseline)

    def test_publication_uses_versioned_destination_without_deleting_live_template(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_template = root / "wineprefix-template-old"
            old_template.mkdir()
            (old_template / "keep").write_text("live", encoding="utf-8")

            def populate(path: Path) -> None:
                path.mkdir(parents=True)
                (path / "system.reg").write_text("seeded", encoding="utf-8")

            with (
                patch.object(wine, "BUILD_DIR", root),
                patch.object(wine, "populate_wine_prefix", side_effect=populate),
                patch.object(
                    wine.subprocess,
                    "run",
                    return_value=SimpleNamespace(stdout="wine-10.0\n"),
                ),
            ):
                template = wine.ensure_template_prefix()
                second = wine.ensure_template_prefix()

            self.assertEqual(template, second)
            self.assertTrue((old_template / "keep").is_file())
            stamp = json.loads(
                (template / ".imperialism-template").read_text(encoding="utf-8")
            )
            self.assertEqual(stamp["schema"], wine.PREFIX_TEMPLATE_SCHEMA)
            self.assertTrue((template / "system.reg").is_file())


if __name__ == "__main__":
    unittest.main()
