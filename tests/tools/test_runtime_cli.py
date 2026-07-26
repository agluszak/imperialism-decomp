#!/usr/bin/env python3
"""Contracts for runtime-test suite aggregation and fixture handling."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools.runtime.catalog import RuntimeTestSpec
from tools.runtime.cli import _suite_command, run_one, run_suite
from tools.runtime.runtime_tests import run_test


def suite_args(junit: Path, require_fixtures: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        suite="full",
        jobs=1,
        timeout=300.0,
        seed=1,
        phase_timeout_ms=60_000,
        rerun_seh=False,
        no_gdb=False,
        require_fixtures=require_fixtures,
        junit=junit,
    )


class RuntimeSuiteTests(unittest.TestCase):
    def test_single_run_uses_catalog_timeout_when_not_overridden(self) -> None:
        args = argparse.Namespace(name="custom", seed=1, timeout=None)
        spec = RuntimeTestSpec("custom", ("full",), default_timeout=42.5)
        with (
            patch("tools.runtime.cli.find_test", return_value=spec),
            patch("tools.runtime.runtime_tests.run_test", return_value=0) as run_test_mock,
        ):
            self.assertEqual(run_one(args), 0)
        self.assertEqual(run_test_mock.call_args.args[0].timeout, 42.5)

    def test_suite_command_uses_catalog_timeout_unless_cli_overrides_it(self) -> None:
        args = suite_args(Path("runtime.xml"))
        args.timeout = None
        spec = RuntimeTestSpec("custom", ("full",), default_timeout=42.5)
        with patch("tools.runtime.cli.find_test", return_value=spec):
            command = _suite_command("custom", args)
            self.assertEqual(command[command.index("--timeout") + 1], "42.5")
            args.timeout = 17.0
            command = _suite_command("custom", args)
            self.assertEqual(command[command.index("--timeout") + 1], "17.0")

    def test_skipped_canonical_result_is_not_counted_as_passed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_dir = root / "results"
            result_dir.mkdir()
            junit = root / "runtime.xml"

            def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
                name = command[4]
                status = "skipped" if name == "load_saved_game" else "passed"
                result = {"name": name, "status": status}
                if status == "skipped":
                    result["failure"] = "missing local retail-derived fixture"
                (result_dir / f"{name}.json").write_text(
                    json.dumps(result), encoding="utf-8"
                )
                return SimpleNamespace(returncode=0)

            with (
                patch("tools.runtime.cli.RESULT_DIR", result_dir),
                patch("tools.runtime.cli.subprocess.run", side_effect=fake_run),
            ):
                returncode = run_suite(suite_args(junit))

            suite = ET.parse(junit).getroot()
            self.assertEqual(returncode, 0)
            self.assertEqual(suite.get("skipped"), "1")
            skipped = suite.find("./testcase[@name='load_saved_game']/skipped")
            self.assertIsNotNone(skipped)
            self.assertIn("missing local", skipped.get("message", ""))

    def test_require_fixtures_turns_missing_fixture_into_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_dir = root / "fixtures"
            args = argparse.Namespace(
                name="load_saved_game",
                require_fixtures=True,
            )
            with (
                patch("tools.runtime.runtime_tests.BUILD_DIR", root),
                patch("tools.runtime.runtime_tests.fixture_directory", return_value=fixture_dir),
            ):
                returncode = run_test(args)

            result = json.loads(
                (root / "runtime-results/load_saved_game.json").read_text(encoding="utf-8")
            )
            self.assertEqual(returncode, 1)
            self.assertEqual(result["status"], "failed")

    def test_seh_rerun_uses_an_isolated_artifact_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []

            def fake_execute(**kwargs: object) -> dict:
                run_dir = Path(kwargs["run_dir"])
                calls.append(run_dir)
                run_dir.mkdir(parents=True, exist_ok=True)
                label = run_dir.name if run_dir.name in {"gdb-rerun", "seh-rerun"} else "primary"
                (run_dir / "gdb.log").write_text(label, encoding="utf-8")
                result = {
                    "format_version": 1,
                    "name": "boot_managers",
                    "seed": 1,
                    "status": "failed",
                    "failure": "synthetic failure",
                }
                (run_dir / "result.json").write_text(
                    json.dumps(result), encoding="utf-8"
                )
                return {
                    "classification": "crash",
                    "wine_exit": -1,
                    "inferior_exit_code": -1,
                }

            args = argparse.Namespace(
                name="boot_managers",
                seed=1,
                timeout=30.0,
                phase_timeout_ms=15_000,
                rerun_seh=True,
                no_gdb=False,
                require_fixtures=False,
            )
            with (
                patch("tools.runtime.runtime_tests.BUILD_DIR", root),
                patch("tools.runtime.runtime_tests.execute_run", side_effect=fake_execute),
            ):
                self.assertEqual(run_test(args), 1)

            # A failing run is retried under the debugger before the SEH rerun, so the
            # sequence is primary (bare) -> gdb-rerun -> seh-rerun. Each writes into its
            # own directory, which is what this test is really asserting.
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[1], calls[0] / "gdb-rerun")
            self.assertEqual(calls[2], calls[0] / "seh-rerun")
            self.assertEqual(len({str(call) for call in calls}), 3)
            self.assertEqual((calls[0] / "gdb.log").read_text(encoding="utf-8"), "primary")
            self.assertEqual(
                (calls[1] / "gdb.log").read_text(encoding="utf-8"), "gdb-rerun"
            )
            self.assertEqual(
                (calls[2] / "gdb.log").read_text(encoding="utf-8"), "seh-rerun"
            )


if __name__ == "__main__":
    unittest.main()
