#!/usr/bin/env python3
"""Contracts for runtime display isolation."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.display import virtual_display


class RuntimeDisplayTests(unittest.TestCase):
    def test_virtual_mode_requires_xvfb_instead_of_inheriting_display(self) -> None:
        environment = {"DISPLAY": ":77"}
        with (
            patch.dict(os.environ, {"IMPERIALISM_RUNTIME_DISPLAY": "virtual"}, clear=False),
            patch("tools.runtime.display._live_worktree_display", return_value=None),
            patch("tools.runtime.display._xvfb_binary", return_value=None),
            self.assertRaisesRegex(RuntimeError, "requires Xvfb"),
        ):
            with virtual_display(environment):
                pass
        self.assertEqual(environment["DISPLAY"], ":77")

    def test_host_mode_is_the_only_implicit_desktop_path(self) -> None:
        environment = {"DISPLAY": ":77"}
        with patch.dict(
            os.environ, {"IMPERIALISM_RUNTIME_DISPLAY": "host"}, clear=False
        ):
            with virtual_display(environment) as selected:
                self.assertIsNone(selected)
        self.assertEqual(environment["DISPLAY"], ":77")


if __name__ == "__main__":
    unittest.main()
