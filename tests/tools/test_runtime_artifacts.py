#!/usr/bin/env python3
"""Contracts for failure artifact capture."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.artifacts import capture_failure_screenshot


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


if __name__ == "__main__":
    unittest.main()
