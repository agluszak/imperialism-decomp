"""Tests for the runtime-test incremental build's configure and regeneration decisions.

The digest makes the configure explicit when the source set moves. It is *not* the only thing
standing between an author and a stale binary: measured on this tree, CMake's CONFIGURE_DEPENDS
re-globs during the build and re-runs the configure itself, so a newly added `src/game/*.cpp`
compiles even under BUILD_ONLY=1. What the build cannot notice on its own is a generated tree
that no longer matches the source model -- stubs and UI factories are only rewritten when
`tools.generate` runs -- which is what `regenerate_sources_if_stale` covers.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.runtime import incremental_build
from tools.runtime.incremental_build import (
    SOURCE_GLOBS,
    newest_generated_input,
    regenerate_sources_if_stale,
    source_set_digest,
)


class SourceSetDigestTest(unittest.TestCase):
    def _repo(self, root: Path, names: list[str]) -> None:
        scenarios = root / "tests" / "runtime" / "native" / "scenarios"
        scenarios.mkdir(parents=True, exist_ok=True)
        for name in names:
            (scenarios / name).write_text("// probe\n", encoding="utf-8")

    def test_content_changes_do_not_change_the_digest(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(root, ["AlphaTest.cpp", "BetaTest.cpp"])
            before = source_set_digest(root)
            target = root / "tests" / "runtime" / "native" / "scenarios" / "AlphaTest.cpp"
            target.write_text("// entirely different body\n", encoding="utf-8")
            self.assertEqual(source_set_digest(root), before)

    def test_adding_a_source_changes_the_digest(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(root, ["AlphaTest.cpp"])
            before = source_set_digest(root)
            self._repo(root, ["GammaTest.cpp"])
            self.assertNotEqual(source_set_digest(root), before)

    def test_removing_a_source_changes_the_digest(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(root, ["AlphaTest.cpp", "BetaTest.cpp"])
            before = source_set_digest(root)
            (root / "tests" / "runtime" / "native" / "scenarios" / "BetaTest.cpp").unlink()
            self.assertNotEqual(source_set_digest(root), before)

    def test_digest_is_order_independent(self):
        with TemporaryDirectory() as first_raw, TemporaryDirectory() as second_raw:
            first, second = Path(first_raw), Path(second_raw)
            self._repo(first, ["AlphaTest.cpp", "BetaTest.cpp"])
            self._repo(second, ["BetaTest.cpp", "AlphaTest.cpp"])
            self.assertEqual(source_set_digest(first), source_set_digest(second))

    def test_headers_are_not_part_of_the_set(self):
        """A header edit needs a rebuild, never a reconfigure: CMake does not glob headers."""
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(root, ["AlphaTest.cpp"])
            before = source_set_digest(root)
            scenarios = root / "tests" / "runtime" / "native" / "scenarios"
            (scenarios / "NewHeader.h").write_text("#pragma once\n", encoding="utf-8")
            self.assertEqual(source_set_digest(root), before)

    def test_globs_match_the_cmake_glob(self):
        """Drift here silently reintroduces the missed-new-file bug."""
        cmake = Path("CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("tests/runtime/native/*.cpp", cmake)
        self.assertEqual(SOURCE_GLOBS, ("tests/runtime/native/**/*.cpp",))


class GeneratedTreeStalenessTest(unittest.TestCase):
    """A marker or ownership edit changes which stubs exist; only `tools.generate` writes them."""

    def _repo(self, root: Path) -> Path:
        (root / "src" / "game").mkdir(parents=True)
        (root / "include" / "game").mkdir(parents=True)
        (root / "config").mkdir(parents=True)
        build = root / "build-runtime-tests"
        (build / "generated").mkdir(parents=True)
        return build

    def test_fresh_generation_is_left_alone(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            build = self._repo(root)
            (root / "src" / "game" / "TThing.cpp").write_text("// body\n", encoding="utf-8")
            model = build / "generated" / "source_model.json"
            model.write_text("{}\n", encoding="utf-8")
            os.utime(model, (2_000_000_000, 2_000_000_000))
            with patch.object(incremental_build.subprocess, "run") as run:
                self.assertFalse(regenerate_sources_if_stale(root, build))
                run.assert_not_called()

    def test_a_newer_manual_source_regenerates(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            build = self._repo(root)
            model = build / "generated" / "source_model.json"
            model.write_text("{}\n", encoding="utf-8")
            os.utime(model, (1_000_000_000, 1_000_000_000))
            source = root / "src" / "game" / "TThing.cpp"
            source.write_text("// edited after the last generation\n", encoding="utf-8")
            os.utime(source, (2_000_000_000, 2_000_000_000))
            with patch.object(incremental_build.subprocess, "run") as run:
                self.assertTrue(regenerate_sources_if_stale(root, build))
                self.assertIn("tools.generate", run.call_args[0][0])

    def test_a_missing_generation_regenerates(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            build = self._repo(root)
            with patch.object(incremental_build.subprocess, "run") as run:
                self.assertTrue(regenerate_sources_if_stale(root, build))
                run.assert_called_once()

    def test_registry_is_not_regenerated_on_every_run(self):
        """The generator leaves the .inc alone when unchanged, so its mtime cannot be the test.

        Comparing the output's mtime against the catalog's re-ran the generator on every single
        invocation of the inner loop, and printed "regenerated" each time -- output that trains
        an author to stop reading it.
        """
        with TemporaryDirectory() as raw:
            root = Path(raw)
            build = self._repo(root)
            (root / "tools" / "runtime").mkdir(parents=True)
            (root / "tools" / "runtime" / "catalog.py").write_text("TESTS = ()\n", encoding="utf-8")
            (root / "tools" / "runtime" / "generate_native_registry.py").write_text(
                "# generator\n", encoding="utf-8"
            )
            output = build / "generated" / "runtime" / "RuntimeRegistry.inc"
            output.parent.mkdir(parents=True)

            def fake_run(*_args, **_kwargs):
                # Mimic the real generator: write only when the content differs, which leaves
                # an unchanged file's mtime behind the catalog's forever.
                if not output.exists():
                    output.write_text("// registry\n", encoding="utf-8")
                    os.utime(output, (1_000_000_000, 1_000_000_000))
                return None

            with patch.object(incremental_build.subprocess, "run", side_effect=fake_run):
                self.assertTrue(incremental_build.regenerate_registry_if_stale(root, build))
                self.assertFalse(incremental_build.regenerate_registry_if_stale(root, build))
                self.assertFalse(incremental_build.regenerate_registry_if_stale(root, build))

    def test_a_catalog_edit_still_regenerates_the_registry(self):
        with TemporaryDirectory() as raw:
            root = Path(raw)
            build = self._repo(root)
            (root / "tools" / "runtime").mkdir(parents=True)
            catalog = root / "tools" / "runtime" / "catalog.py"
            catalog.write_text("TESTS = ()\n", encoding="utf-8")
            (root / "tools" / "runtime" / "generate_native_registry.py").write_text(
                "# generator\n", encoding="utf-8"
            )
            output = build / "generated" / "runtime" / "RuntimeRegistry.inc"
            output.parent.mkdir(parents=True)
            output.write_text("// registry\n", encoding="utf-8")

            with patch.object(incremental_build.subprocess, "run"):
                incremental_build.regenerate_registry_if_stale(root, build)
                self.assertFalse(incremental_build.regenerate_registry_if_stale(root, build))
                os.utime(catalog, (2_000_000_000, 2_000_000_000))
                self.assertTrue(incremental_build.regenerate_registry_if_stale(root, build))

    def test_config_inputs_count_as_sources(self):
        """An ownership CSV edit changes the generated stubs without touching any .cpp."""
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self._repo(root)
            csv = root / "config" / "original_entities.csv"
            csv.write_text("address,name\n", encoding="utf-8")
            os.utime(csv, (2_000_000_000, 2_000_000_000))
            self.assertEqual(2_000_000_000, newest_generated_input(root))


if __name__ == "__main__":
    unittest.main()
