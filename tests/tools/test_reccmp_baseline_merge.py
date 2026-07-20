#!/usr/bin/env python3
"""Tests for generated reccmp baseline Git integration."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.workflow.reccmp_baseline_merge import (
    SKIP_ENV,
    install,
    mark_pending,
    refresh_pending,
    run_merge_driver,
)


class ReccmpBaselineMergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.marker = self.root / "pending"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_pending_paths_are_deduplicated_and_sorted(self) -> None:
        mark_pending(self.marker, "z.json")
        mark_pending(self.marker, "a.json")
        mark_pending(self.marker, "z.json")
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "a.json\nz.json\n")

    @patch("tools.workflow.reccmp_baseline_merge.pending_path")
    def test_merge_driver_marks_expected_baseline(self, pending) -> None:
        pending.return_value = self.marker
        path = "config/baselines/reccmp_progress_baseline.functions.csv"
        self.assertEqual(run_merge_driver(self.root, path), 0)
        self.assertEqual(self.marker.read_text(encoding="utf-8"), f"{path}\n")

    def test_merge_driver_rejects_unexpected_path(self) -> None:
        self.assertEqual(run_merge_driver(self.root, "src/game/TView.cpp"), 1)

    def test_git_merge_driver_defers_real_json_conflict(self) -> None:
        baseline = self.root / "config/baselines/reccmp_progress_baseline.json"
        attributes = self.root / ".gitattributes"
        baseline.parent.mkdir(parents=True)
        baseline.write_text('{"version": "base"}\n', encoding="utf-8")
        attributes.write_text(
            f"{baseline.relative_to(self.root)} merge=reccmp-baseline\n",
            encoding="utf-8",
        )
        commands = (
            ["git", "init", "-b", "main"],
            ["git", "config", "user.email", "test@example.com"],
            ["git", "config", "user.name", "Test"],
            ["git", "add", "."],
            ["git", "commit", "-m", "base"],
            ["git", "switch", "-c", "other"],
        )
        for command in commands:
            subprocess.run(command, cwd=self.root, check=True, capture_output=True)
        baseline.write_text('{"version": "other"}\n', encoding="utf-8")
        subprocess.run(
            ["git", "commit", "-am", "other"],
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "switch", "main"], cwd=self.root, check=True, capture_output=True
        )
        baseline.write_text('{"version": "current"}\n', encoding="utf-8")
        subprocess.run(
            ["git", "commit", "-am", "current"],
            cwd=self.root,
            check=True,
            capture_output=True,
        )

        driver_script = (
            Path(__file__).resolve().parents[2]
            / "tools/workflow/reccmp_baseline_merge.py"
        )
        driver = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(driver_script))} "
            "merge-driver %O %A %B %P"
        )
        subprocess.run(
            ["git", "config", f"merge.reccmp-baseline.driver", driver],
            cwd=self.root,
            check=True,
        )
        merge = subprocess.run(
            ["git", "merge", "--no-commit", "other"],
            cwd=self.root,
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(merge.returncode, 0, merge.stderr)
        self.assertEqual(
            baseline.read_text(encoding="utf-8"), '{"version": "current"}\n'
        )
        self.assertTrue((self.root / ".git" / "reccmp-baseline-refresh.pending").exists())

    @patch("tools.workflow.reccmp_baseline_merge.subprocess.run")
    def test_install_accepts_absolute_beads_hook_path(self, run) -> None:
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if "--get" in command:
                return SimpleNamespace(stdout=f"{self.root}/.beads/hooks\n")
            return SimpleNamespace(stdout="")

        run.side_effect = fake_run
        self.assertEqual(install(self.root), 0)
        self.assertIn(
            ["git", "config", "--local", "core.hooksPath", ".beads/hooks"],
            calls,
        )

    @patch("tools.workflow.reccmp_baseline_merge._git_output", return_value="")
    def test_refresh_runs_build_and_stats_then_clears_marker(self, _git_output) -> None:
        self.marker.write_text("baseline.json\n", encoding="utf-8")
        calls = []

        def runner(command, cwd):
            calls.append((list(command), cwd))

        result = refresh_pending(
            self.root,
            self.marker,
            event="post-rewrite",
            runner=runner,
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            calls,
            [
                (["just", "build"], self.root),
                (["just", "stats-baseline-update"], self.root),
            ],
        )
        self.assertFalse(self.marker.exists())

    @patch("tools.workflow.reccmp_baseline_merge._git_output", return_value="")
    def test_squash_merge_defers_to_post_commit(self, _git_output) -> None:
        self.marker.write_text("baseline.json\n", encoding="utf-8")
        calls = []
        self.assertEqual(
            refresh_pending(
                self.root,
                self.marker,
                event="post-merge",
                squash=True,
                runner=lambda command, cwd: calls.append(command),
            ),
            0,
        )
        self.assertEqual(calls, [])
        self.assertTrue(self.marker.exists())

    @patch("tools.workflow.reccmp_baseline_merge._git_output", return_value="")
    def test_environment_can_defer_refresh(self, _git_output) -> None:
        self.marker.write_text("baseline.json\n", encoding="utf-8")
        with patch.dict(os.environ, {SKIP_ENV: "1"}):
            self.assertEqual(
                refresh_pending(
                    self.root,
                    self.marker,
                    event="post-commit",
                    runner=lambda command, cwd: self.fail("runner called"),
                ),
                0,
            )
        self.assertTrue(self.marker.exists())

    @patch("tools.workflow.reccmp_baseline_merge._git_output", return_value="")
    def test_failed_refresh_keeps_marker(self, _git_output) -> None:
        self.marker.write_text("baseline.json\n", encoding="utf-8")

        def fail(_command, _cwd):
            raise subprocess.CalledProcessError(1, "just build")

        self.assertEqual(
            refresh_pending(
                self.root,
                self.marker,
                event="post-commit",
                strict=True,
                runner=fail,
            ),
            1,
        )
        self.assertTrue(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
