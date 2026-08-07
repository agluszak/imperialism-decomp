"""Tests for the repository-hygiene gate (bd imperialism-decomp-ej4d).

Each test builds a throwaway git repo and tracks a file in it, so the assertions are about
what `git ls-files` actually reports rather than about string matching on a path list. The
categories under test are the ones that were empty when the gate was written -- if one of
them ever becomes legitimately non-empty, the corresponding test is the place that has to
justify the exemption.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.workflow.check_repo_hygiene import DEFAULT_MAX_BINARY_BYTES, find_offenders


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


class RepoHygieneTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        _git(self.repo, "init", "-q")
        self.addCleanup(self._tmp.cleanup)

    def _track(self, relative: str, content: bytes = b"x") -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        # -f because the point of several of these paths is that .gitignore would
        # normally hide them; the gate exists for when that protection is bypassed.
        _git(self.repo, "add", "-f", relative)

    def _offenders(self) -> dict[str, str]:
        return dict(find_offenders(self.repo, DEFAULT_MAX_BINARY_BYTES))

    def test_clean_repo_passes(self) -> None:
        self._track("src/game/TFoo.cpp", b"int main() { return 0; }\n")
        self.assertEqual(self._offenders(), {})

    def test_rejects_the_clangd_cache_that_motivated_the_gate(self) -> None:
        self._track(".cache/clangd/index/TFoo.cpp.idx")
        self.assertIn(".cache/clangd/index/TFoo.cpp.idx", self._offenders())

    def test_rejects_banned_directories_at_any_depth(self) -> None:
        self._track("tools/workflow/__pycache__/check.cpython-313.pyc")
        offenders = self._offenders()
        self.assertIn("tools/workflow/__pycache__/check.cpython-313.pyc", offenders)

    def test_rejects_compiler_and_editor_output_by_extension(self) -> None:
        for relative in ("a.obj", "b.exe", "c.pdb", "d.ilk", "e.ncb"):
            self._track(relative)
        self.assertEqual(len(self._offenders()), 5)

    def test_rejects_build_trees(self) -> None:
        self._track("build/CMakeCache.txt")
        self.assertIn("build/CMakeCache.txt", self._offenders())

    def test_rejects_stray_logs_but_exempts_the_vendored_fid_logs(self) -> None:
        self._track("runtime-results/session.log")
        self._track("vendor/msvc500/fid-generation/logs/import.log")
        offenders = self._offenders()
        self.assertIn("runtime-results/session.log", offenders)
        self.assertNotIn("vendor/msvc500/fid-generation/logs/import.log", offenders)

    def test_large_text_evidence_is_allowed(self) -> None:
        # The Mac crosswalks and vtable ABI evidence are multi-MB JSON. Size alone must
        # not condemn a file, or the gate would fail on the tree it ships with.
        self._track("docs/reference/mac_string_crosswalk.json", b"[" + b" " * (2 << 20) + b"]")
        self.assertEqual(self._offenders(), {})

    def test_large_binary_outside_vendor_is_rejected(self) -> None:
        self._track("resources/blob.dat", b"\0" + b"y" * (2 << 20))
        offenders = self._offenders()
        self.assertIn("resources/blob.dat", offenders)
        self.assertIn("binary", offenders["resources/blob.dat"])

    def test_small_binary_outside_vendor_is_allowed(self) -> None:
        # Icons and small fixtures are binary but unremarkable; only bulk is the concern.
        self._track("resources/icon.ico", b"\0\0\1\0")
        self.assertEqual(self._offenders(), {})

    def test_large_binary_under_vendor_is_allowed(self) -> None:
        self._track("vendor/ghidra/exports/Imperialism.gzf", b"\0" + b"z" * (2 << 20))
        self.assertEqual(self._offenders(), {})


if __name__ == "__main__":
    unittest.main()
