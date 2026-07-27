#!/usr/bin/env python3
"""Contracts for failure artifact capture and run-bundle retention."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.artifacts import (
    BUNDLE_RETENTION,
    RETENTION_ENV,
    bundle_retention,
    capture_failure_screenshot,
    prune_old_run_dirs,
    remove_run_dir,
    stale_run_dirs,
)


def make_bundle(result_dir: Path, name: str, stamp: str, *, read_only: bool = False) -> Path:
    """A run bundle shaped like the real one: a staged game/ tree under a timestamp."""
    bundle = result_dir / f"{name}-{stamp}-123"
    data = bundle / "game" / "Data"
    data.mkdir(parents=True)
    (bundle / "result.json").write_text("{}", encoding="utf-8")
    asset = data / "pictwv1.gob"
    asset.write_bytes(b"asset")
    if read_only:
        asset.chmod(0o444)
        data.chmod(0o555)
        (bundle / "game").chmod(0o555)
    return bundle


class RuntimeArtifactTests(unittest.TestCase):
    def test_screenshot_uses_the_existing_tooling_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "failure.png"
            with patch("tools.runtime.artifacts.subprocess.run") as run:
                capture_failure_screenshot(destination, owner_pid=42)
        command = run.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertNotIn("uv", command)
        self.assertNotIn("--with", command)
        self.assertIn("--pid", command)


class RunBundleRemovalTests(unittest.TestCase):
    """The staged assets are read-only, which is what defeated the old retention."""

    def test_read_only_sandbox_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(root, "boot_managers", "20260101T000000Z", read_only=True)
            self.assertTrue(remove_run_dir(bundle))
            self.assertFalse(bundle.exists())

    def test_writable_bundle_and_missing_bundle_both_report_gone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(root, "boot_managers", "20260101T000000Z")
            self.assertTrue(remove_run_dir(bundle))
            self.assertTrue(remove_run_dir(root / "never-existed"))


class RetentionSelectionTests(unittest.TestCase):
    def _bundles(self, root: Path, name: str, stamps: tuple[str, ...]) -> list[Path]:
        return [make_bundle(root, name, stamp) for stamp in stamps]

    def test_keeps_the_newest_and_returns_the_rest_oldest_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stamps = ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z")
            self._bundles(root, "boot_managers", stamps)
            stale = stale_run_dirs(root, "boot_managers", 1)
            self.assertEqual([path.name.split("-")[1] for path in stale], list(stamps[:2]))

    def test_keep_zero_selects_every_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._bundles(root, "boot_managers", ("20260101T000000Z", "20260102T000000Z"))
            self.assertEqual(len(stale_run_dirs(root, "boot_managers", 0)), 2)

    def test_a_longer_test_name_sharing_a_prefix_is_not_swept_up(self) -> None:
        """easy_turns_advance must not prune easy_turns_advance_three_times."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._bundles(root, "easy_turns_advance", ("20260101T000000Z",))
            sibling = make_bundle(root, "easy_turns_advance_three_times", "20260101T000000Z")
            self.assertEqual(stale_run_dirs(root, "easy_turns_advance", 0), 
                             [root / "easy_turns_advance-20260101T000000Z-123"])
            self.assertTrue(sibling.exists())


class PruneReportingTests(unittest.TestCase):
    def test_prune_removes_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for stamp in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
                make_bundle(root, "boot_managers", stamp, read_only=True)
            removed, survivors = prune_old_run_dirs(root, "boot_managers", keep=1)
            self.assertEqual(removed, 2)
            self.assertEqual(survivors, [])
            self.assertEqual(len([p for p in root.iterdir() if p.is_dir()]), 1)


class RetentionSettingTests(unittest.TestCase):
    def test_environment_overrides_the_default(self) -> None:
        with patch.dict(os.environ, {RETENTION_ENV: "7"}, clear=False):
            self.assertEqual(bundle_retention(), 7)
        with patch.dict(os.environ, {RETENTION_ENV: "0"}, clear=False):
            self.assertEqual(bundle_retention(), 0)

    def test_junk_and_absence_fall_back_to_the_default(self) -> None:
        with patch.dict(os.environ, {RETENTION_ENV: "lots"}, clear=False):
            self.assertEqual(bundle_retention(), BUNDLE_RETENTION)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(bundle_retention(), BUNDLE_RETENTION)

    def test_negative_retention_is_clamped_to_zero(self) -> None:
        with patch.dict(os.environ, {RETENTION_ENV: "-3"}, clear=False):
            self.assertEqual(bundle_retention(), 0)


if __name__ == "__main__":
    unittest.main()
