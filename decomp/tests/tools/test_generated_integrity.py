"""Detection tests for check_generated_integrity (bd imperialism-decomp-x1cl).

Thirteenth of the eighteen. Unlike the first twelve this gate has no pure helper to
exercise -- it shells out to `git diff` against a merge base -- so each test builds a
throwaway repo and commits into it, the same shape as tests/tools/test_repo_hygiene.py.

Positive detection tests, for the same reason as the rest of the batch: the failure that
matters is the gate quietly matching nothing and still exiting 0.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.workflow.check_generated_integrity import GENERATED_PREFIXES, changed_paths


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return proc.stdout.strip()


class GeneratedIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        _git(self.repo, "config", "user.name", "Test")
        self._commit("README.md", "base\n", "base commit")
        self.base = _git(self.repo, "rev-parse", "HEAD")

    def _commit(self, relative: str, content: str, message: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        _git(self.repo, "add", "-f", relative)
        _git(self.repo, "commit", "-q", "-m", message)

    def _offenders(self, no_worktree: bool = False) -> list[str]:
        return [
            path
            for path in changed_paths(self.repo, self.base, no_worktree)
            if path.startswith(GENERATED_PREFIXES)
        ]

    def test_a_committed_generated_artifact_is_detected(self) -> None:
        self._commit("build-msvc500/generated/symbols.csv", "a|b\n", "commit a build input")
        self.assertEqual(self._offenders(), ["build-msvc500/generated/symbols.csv"])

    def test_every_generated_prefix_is_covered(self) -> None:
        # If a prefix silently stops matching, the tree it guards becomes committable
        # without anyone noticing -- which is the whole failure mode of this bead.
        for index, prefix in enumerate(GENERATED_PREFIXES):
            with self.subTest(prefix=prefix):
                path = f"{prefix}sample{index}.txt"
                self._commit(path, "x\n", f"commit under {prefix}")
                self.assertIn(path, self._offenders())

    def test_manual_source_is_not_flagged(self) -> None:
        self._commit("src/game/city/TCity.cpp", "void f() {}\n", "manual source")
        self.assertEqual(self._offenders(), [])

    def test_an_uncommitted_generated_artifact_is_caught_by_default(self) -> None:
        # The default includes the worktree, so an artifact staged but not yet committed
        # still fails -- catching it before the commit exists is the point.
        path = self.repo / "build-msvc500" / "stray.o"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
        _git(self.repo, "add", "-f", "build-msvc500/stray.o")
        self.assertIn("build-msvc500/stray.o", self._offenders())

    def test_no_worktree_restricts_the_comparison_to_committed_changes(self) -> None:
        path = self.repo / "build-msvc500" / "stray.o"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
        _git(self.repo, "add", "-f", "build-msvc500/stray.o")
        self.assertEqual(self._offenders(no_worktree=True), [])

    def test_an_unknown_base_is_a_clean_error_not_a_silent_pass(self) -> None:
        # A gate that returns "nothing changed" when it cannot resolve the base would
        # report clean for every branch. It must fail loudly instead.
        with self.assertRaises(SystemExit):
            changed_paths(self.repo, "definitely-not-a-ref", False)


if __name__ == "__main__":
    unittest.main()
