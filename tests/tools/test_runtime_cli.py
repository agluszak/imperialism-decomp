#!/usr/bin/env python3
"""Contracts for runtime-test suite aggregation and fixture handling."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from tools.runtime import runner
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools.runtime.catalog import RuntimeTestSpec
from tools.runtime.cli import _suite_command, run_one, run_suite
from tools.runtime.models import HostResult, RunConfig
from tools.runtime.runner import RunnerDependencies
from tools.runtime.runtime_tests import run_test


def suite_args(junit: Path, require_fixtures: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        suite="full",
        jobs=1,
        timeout=300.0,
        seed=1,
        rerun_seh=False,
        no_gdb=False,
        require_fixtures=require_fixtures,
        junit=junit,
    )


class RuntimeSuiteTests(unittest.TestCase):
    @staticmethod
    def _host(run_dir: Path, classification: str | None = None) -> HostResult:
        return HostResult(
            classification=classification,
            display=":test",
            artifact_dir=run_dir,
            duration_seconds=1.25,
            phase_seconds={"run": 1.0},
            phase="finished",
            action="synthetic_action",
            wine_exit=0,
            proxy_pid=None,
            proxy_exit_code=None,
            gdb_pid=None,
            gdb_exit_code=None,
            inferior_pid=123,
            inferior_exit_code=0,
            inferior_terminal_reason="process-exited",
            inferior_signal=None,
            debugger="none",
            debugger_stop_count=0,
            debugger_transport_error=None,
            debugger_invariant=None,
            debugger_signal=None,
            game_dir=run_dir / "game",
            provenance={},
        )

    def test_single_run_uses_catalog_timeout_when_not_overridden(self) -> None:
        args = argparse.Namespace(name="custom", seed=1, timeout=None)
        spec = RuntimeTestSpec(
            "custom", "CustomTest", ("full",), "internal_invariant", default_timeout=42.5
        )
        with (
            patch("tools.runtime.cli.find_test", return_value=spec),
            patch("tools.runtime.runtime_tests.run_test", return_value=0) as run_test_mock,
        ):
            self.assertEqual(run_one(args), 0)
        self.assertEqual(run_test_mock.call_args.args[0].timeout, 42.5)

    def test_harness_only_catalog_entry_does_not_use_game_runner(self) -> None:
        args = argparse.Namespace(name="harness", seed=1, timeout=None)
        spec = RuntimeTestSpec(
            "harness",
            "RuntimeHarnessSelfTest",
            ("pr",),
            "internal_invariant",
            execution="harness",
            default_timeout=1.0,
        )
        with (
            patch("tools.runtime.cli.find_test", return_value=spec),
            patch(
                "tools.runtime.harness_selftest.run_harness_selftest", return_value=0
            ) as harness,
            patch("tools.runtime.runtime_tests.run_test") as game,
        ):
            self.assertEqual(run_one(args), 0)
        harness.assert_called_once()
        game.assert_not_called()

    def test_suite_command_uses_catalog_timeout_unless_cli_overrides_it(self) -> None:
        args = suite_args(Path("runtime.xml"))
        args.timeout = None
        spec = RuntimeTestSpec(
            "custom", "CustomTest", ("full",), "internal_invariant", default_timeout=42.5
        )
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

    def test_junit_failure_exposes_actionable_attempt_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_dir = root / "results"
            result_dir.mkdir()
            junit = root / "runtime.xml"

            def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
                name = command[4]
                failed = name == "boot_managers"
                result = {
                    "name": name,
                    "status": "failed" if failed else "passed",
                }
                if failed:
                    result["failure"] = "primary crashed"
                    result["summary"] = {
                        "duration_seconds": 2.5,
                        "phase": "waiting_for_managers",
                        "classification": "crash",
                        "action": "wait_for_managers",
                        "artifact_path": "/tmp/runtime-bundle",
                        "primary_failure": "primary crashed",
                        "assertion_id": "managers.initialized",
                        "diagnostic_outcomes": [
                            {
                                "kind": "diagnostic_gdb",
                                "status": "passed",
                                "classification": None,
                            }
                        ],
                    }
                (result_dir / f"{name}.json").write_text(
                    json.dumps(result), encoding="utf-8"
                )
                return SimpleNamespace(returncode=1 if failed else 0)

            with (
                patch("tools.runtime.cli.RESULT_DIR", result_dir),
                patch("tools.runtime.cli.subprocess.run", side_effect=fake_run),
            ):
                self.assertEqual(run_suite(suite_args(junit)), 1)

            suite = ET.parse(junit).getroot()
            case = suite.find("./testcase[@name='boot_managers']")
            self.assertIsNotNone(case)
            self.assertEqual(case.get("time"), "2.5")
            failure = case.find("failure")
            self.assertIn("phase=waiting_for_managers", failure.get("message", ""))
            self.assertIn("classification=crash", failure.get("message", ""))
            self.assertIn("action=wait_for_managers", failure.get("message", ""))
            self.assertIn("assertion=managers.initialized", failure.get("message", ""))
            self.assertIn("artifacts=/tmp/runtime-bundle", failure.get("message", ""))
            self.assertIn("diagnostic_gdb=passed/none", failure.get("message", ""))

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

            def fake_execute(config: RunConfig) -> HostResult:
                run_dir = config.run_dir
                calls.append(run_dir)
                run_dir.mkdir(parents=True, exist_ok=True)
                label = "primary" if len(calls) == 1 else run_dir.name
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
                return HostResult(
                    **{
                        **self._host(run_dir, "crash").__dict__,
                        "wine_exit": -1,
                        "inferior_exit_code": -1,
                    }
                )

            args = argparse.Namespace(
                name="boot_managers",
                seed=1,
                timeout=30.0,
                rerun_seh=True,
                no_gdb=False,
                require_fixtures=False,
            )
            with (
                patch("tools.runtime.runtime_tests.BUILD_DIR", root),
            ):
                self.assertEqual(
                    run_test(args, RunnerDependencies(execute=fake_execute)), 1
                )

            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[1], calls[0] / "gdb-rerun")
            self.assertEqual(calls[2], calls[0] / "seh-rerun")
            self.assertEqual((calls[0] / "gdb.log").read_text(encoding="utf-8"), "primary")
            self.assertEqual(
                (calls[1] / "gdb.log").read_text(encoding="utf-8"), "gdb-rerun"
            )
            self.assertEqual(
                (calls[2] / "gdb.log").read_text(encoding="utf-8"), "seh-rerun"
            )

    def test_diagnostic_pass_cannot_replace_failed_primary_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []

            def fake_execute(config: RunConfig) -> HostResult:
                run_dir = config.run_dir
                calls.append(run_dir)
                status = "failed" if len(calls) == 1 else "passed"
                native = {
                    "format_version": 1,
                    "name": "boot_managers",
                    "seed": 1,
                    "status": status,
                }
                if status == "failed":
                    native["failure"] = "bare Wine failure"
                (run_dir / "result.json").write_text(json.dumps(native), encoding="utf-8")
                return self._host(run_dir)

            args = argparse.Namespace(
                name="boot_managers",
                seed=1,
                timeout=30.0,
                rerun_seh=False,
                no_gdb=False,
                require_fixtures=False,
            )
            with (
                patch("tools.runtime.runtime_tests.BUILD_DIR", root),
            ):
                self.assertEqual(
                    run_test(args, RunnerDependencies(execute=fake_execute)), 1
                )

            result = json.loads(
                (root / "runtime-results/boot_managers.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure"], "bare Wine failure")
            self.assertEqual(result["classification"], "debugger_sensitive_non_reproduction")
            self.assertEqual([attempt["authoritative"] for attempt in result["attempts"]], [True, False])
            self.assertEqual(result["attempts"][1]["status"], "passed")
            self.assertTrue((calls[0] / "native-result.json").is_file())
            self.assertTrue((calls[1] / "native-result.json").is_file())

    def test_oracle_errors_and_mismatches_coexist_with_native_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def fake_execute(config: RunConfig) -> HostResult:
                run_dir = config.run_dir
                native = {
                    "format_version": 1,
                    "name": "random_game_easy_skips_capital",
                    "seed": 1,
                    "status": "passed",
                    "ui_snapshots": [{"event": 1}],
                    "map_state": {"wrap": 0},
                }
                (run_dir / "result.json").write_text(json.dumps(native), encoding="utf-8")
                return self._host(run_dir)

            args = argparse.Namespace(
                name="random_game_easy_skips_capital",
                seed=1,
                timeout=30.0,
                rerun_seh=False,
                no_gdb=True,
                require_fixtures=False,
            )
            with (
                patch("tools.runtime.runtime_tests.BUILD_DIR", root),
            ):
                dependencies = RunnerDependencies(
                    execute=fake_execute,
                    ui_oracle=lambda _result: (_ for _ in ()).throw(
                        ValueError("broken UI model")
                    ),
                    map_oracle=lambda _result, _name, _seed: {
                        "status": "failed",
                        "differences": {"wrap": {}},
                    },
                )
                self.assertEqual(run_test(args, dependencies), 1)

            result = json.loads(
                (
                    root
                    / "runtime-results/random_game_easy_skips_capital.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(result["ui_oracle"]["status"], "error")
            self.assertEqual(result["map_oracle"]["status"], "failed")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["attempts"][0]["native"]["status"], "passed")
            self.assertIn("map oracle mismatch", result["secondary_failures"])


if __name__ == "__main__":
    unittest.main()


class OutcomeExitCodeTests(unittest.TestCase):
    """A matched ExpectedFailureSpec must not still fail the run.

    ExpectedFailureSpec.classifications lets a spec name the classification a crash
    produces; before this, the classification forced exit 1 regardless, so declaring one
    was pointless -- the repro suite went red while reporting the failure as expected.
    """

    def test_matched_expectation_exits_zero_even_for_a_crashed_inferior(self):
        self.assertEqual(runner.outcome_exit_code("expected_failure", "heartbeat_stopped", 5), 0)
        self.assertEqual(runner.outcome_exit_code("expected_failure", None, None), 0)

    def test_unexpected_classification_or_inferior_exit_still_fails(self):
        self.assertEqual(runner.outcome_exit_code("passed", "crash", 0), 1)
        self.assertEqual(runner.outcome_exit_code("passed", None, 3), 1)

    def test_plain_pass_and_plain_failure(self):
        self.assertEqual(runner.outcome_exit_code("passed", None, 0), 0)
        self.assertEqual(runner.outcome_exit_code("failed", None, 0), 1)
        self.assertEqual(runner.outcome_exit_code(None, None, 0), 1)
