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

            def populate(path: Path, virtual_desktop: bool = False) -> None:
                del virtual_desktop
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


class RuntimeRegistryTests(unittest.TestCase):
    def test_each_attempt_deletes_and_reseeds_the_game_settings_key(self) -> None:
        with patch.object(wine.subprocess, "run") as run:
            wine.seed_runtime_registry({"WINEPREFIX": "/tmp/prefix"})
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            commands[0], ["wine", "reg", "delete", wine.SETTINGS_KEY, "/f"]
        )
        self.assertEqual(len(commands), 1 + len(wine.SEEDED_REGISTRY_VALUES))
        for name, _value_type, value in wine.SEEDED_REGISTRY_VALUES:
            matching = [command for command in commands[1:] if name in command]
            self.assertEqual(len(matching), 1)
            self.assertIn(value, matching[0])


class GameSandboxTests(unittest.TestCase):
    def test_attempts_get_clean_writable_trees_with_read_only_cached_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retail = root / "retail"
            (retail / "Data").mkdir(parents=True)
            (retail / "Data" / "asset.gob").write_bytes(b"asset")
            (retail / "Save").mkdir()
            (retail / "Save" / "contamination.imp").write_bytes(b"old")
            (retail / "Imperialism.exe").write_bytes(b"retail")
            runtime_executable = root / "runtime" / "Imperialism.exe"
            runtime_executable.parent.mkdir()
            runtime_executable.write_bytes(b"instrumented")
            runtime_executable.with_suffix(".map").write_text("map", encoding="utf-8")
            fixture = root / "fixture.imp"
            fixture.write_bytes(b"fixture")

            with (
                patch.object(wine, "BUILD_DIR", root / "build"),
                patch.object(wine, "retail_game_dir", return_value=retail),
            ):
                game1, staged_fixture, identity1 = wine.prepare_game_sandbox(
                    root / "attempt-1", runtime_executable, fixture
                )
                cached_asset = next((root / "build").glob("game-assets-*/Data/asset.gob"))
                # Assets are shared with the immutable template rather than duplicated
                # per attempt: copying them cost ~237MB a run. Cross-attempt isolation
                # now comes from the template being read-only, not from duplication --
                # a stronger guarantee, since a stray write fails instead of silently
                # diverging one attempt's copy.
                staged_asset = game1 / "Data" / "asset.gob"
                self.assertTrue(staged_asset.is_symlink())
                self.assertEqual(staged_asset.resolve(), cached_asset.resolve())
                with self.assertRaises(PermissionError):
                    staged_asset.open("wb")

                # Directories are real, so the game can still create new files.
                (game1 / "Data" / "scratch.tmp").write_bytes(b"scratch")
                (game1 / "Save" / "new.imp").write_bytes(b"new")
                game2, _, identity2 = wine.prepare_game_sandbox(
                    root / "attempt-2", runtime_executable
                )

            self.assertNotEqual(game1, retail)
            self.assertEqual(identity1, identity2)
            self.assertEqual((game1 / "Imperialism.exe").read_bytes(), b"instrumented")
            # The instrumented binary is a real file, not a link into the template --
            # it is the one thing that differs between attempts.
            self.assertFalse((game1 / "Imperialism.exe").is_symlink())
            self.assertFalse((game1 / "Save" / "contamination.imp").exists())
            self.assertFalse((game2 / "Save" / "new.imp").exists())
            self.assertFalse((game2 / "Data" / "scratch.tmp").exists())
            self.assertEqual((game2 / "Data" / "asset.gob").read_bytes(), b"asset")
            self.assertEqual((game2 / "Data" / "asset.gob").stat().st_mode & 0o222, 0)
            self.assertEqual((retail / "Data" / "asset.gob").read_bytes(), b"asset")
            self.assertEqual(
                (retail / "Save" / "contamination.imp").read_bytes(), b"old"
            )
            self.assertFalse((retail / "Save" / "new.imp").exists())
            self.assertIsNotNone(staged_fixture)
            self.assertEqual(staged_fixture.read_bytes(), b"fixture")
            self.assertEqual(staged_fixture.stat().st_mode & 0o222, 0)


if __name__ == "__main__":
    unittest.main()
