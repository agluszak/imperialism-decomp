"""Tests for the runtime-test incremental build's configure decision.

The dangerous mistake this guards is silent: CMake re-evaluates its CONFIGURE_DEPENDS globs
during a configure, not during a build, so skipping the configure after a scenario `.cpp` is
added means the new file is simply never compiled -- and the test it registers then fails to
link or, worse, runs the previous binary. The digest is what makes that impossible.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.runtime.incremental_build import SOURCE_GLOBS, source_set_digest


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


if __name__ == "__main__":
    unittest.main()
