#!/usr/bin/env python3
"""Contracts for manual runtime smoke/debug lifecycle commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools.runtime.smoke import cmd_gdb


class ManualGdbLifecycleTests(unittest.TestCase):
    def args(self, keep_running: bool) -> argparse.Namespace:
        return argparse.Namespace(
            script=None,
            ex=["continue"],
            port=47632,
            seconds=0.1,
            keep_running=keep_running,
        )

    def test_keep_running_preserves_proxy_and_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            proxy = Mock()
            proxy.process = SimpleNamespace(pid=4321)
            with (
                patch(
                    "tools.runtime.smoke.create_wine_prefix",
                    return_value=(prefix, {"WINEPREFIX": str(prefix)}),
                ),
                patch("tools.runtime.smoke.launch_proxy", return_value=proxy),
                patch("tools.runtime.smoke.run_gdb", return_value="done"),
                patch("tools.runtime.smoke.shut_down_wine_prefix") as shutdown,
            ):
                self.assertEqual(cmd_gdb(self.args(True)), 0)
            proxy.close.assert_not_called()
            shutdown.assert_not_called()

    def test_default_mode_closes_proxy_and_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            environment = {"WINEPREFIX": str(prefix)}
            proxy = Mock()
            proxy.process = SimpleNamespace(pid=4321)
            with (
                patch(
                    "tools.runtime.smoke.create_wine_prefix",
                    return_value=(prefix, environment),
                ),
                patch("tools.runtime.smoke.launch_proxy", return_value=proxy),
                patch("tools.runtime.smoke.run_gdb", return_value="done"),
                patch("tools.runtime.smoke.shut_down_wine_prefix") as shutdown,
            ):
                self.assertEqual(cmd_gdb(self.args(False)), 0)
            proxy.close.assert_called_once_with()
            shutdown.assert_called_once_with(prefix, environment)


if __name__ == "__main__":
    unittest.main()
