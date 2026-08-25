#!/usr/bin/env python3
"""Native transition launch bypasses RuntimeRunner."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.models import HostResult, RunConfig
from tools.runtime.native_oracle import run_native_transition
from tools.runtime.runner import RuntimeRunner


def host_result(run_dir: Path, classification: str | None = None, exit_code: int = 0) -> HostResult:
    return HostResult(
        classification=classification,
        display=":test",
        artifact_dir=run_dir,
        duration_seconds=1.0,
        phase_seconds={"run": 1.0},
        phase="finished",
        action="native_transition",
        wine_exit=0,
        proxy_pid=None,
        proxy_exit_code=None,
        gdb_pid=None,
        gdb_exit_code=None,
        inferior_pid=123,
        inferior_exit_code=exit_code,
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


class NativeOracleTests(unittest.TestCase):
    def write_native_bundle(self, run_dir: Path, *, status: str = "passed") -> None:
        captures = {
            "before": {"turn": {"economic_turn": 1}},
            "case": {"nation": 6},
            "after": {"turn": {"economic_turn": 1}},
            "result": True,
        }
        (run_dir / "captures.json").write_text(
            json.dumps(captures) + "\n", encoding="utf-8"
        )
        (run_dir / "result.json").write_text(
            json.dumps(
                {
                    "name": "native_transition_oracle",
                    "seed": 1,
                    "status": status,
                    "captures_path": "captures.json",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def write_save_backed_bundle(self, run_dir: Path) -> None:
        save_dir = run_dir / "game" / "Save"
        save_dir.mkdir(parents=True)
        (save_dir / "rt_native_before.imp").write_bytes(b"before-bytes")
        (save_dir / "rt_native_after.imp").write_bytes(b"after-bytes")
        captures = {
            "before": {"save": "before.imp", "ephemeral": {"turn": 1}},
            "case": {"nation": 6},
            "after": {"save": "after.imp", "ephemeral": {"turn": 1}},
            "result": True,
        }
        (run_dir / "captures.json").write_text(
            json.dumps(captures) + "\n", encoding="utf-8"
        )
        (run_dir / "result.json").write_text(
            json.dumps(
                {
                    "name": "native_transition_oracle",
                    "seed": 1,
                    "status": "passed",
                    "captures_path": "captures.json",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def test_snapshot_captures_do_not_require_save_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            fixture_dir = root / "fixtures"
            fixture_dir.mkdir()
            (fixture_dir / "beginning_of_game.imp").write_bytes(b"fixture")
            runner_used = False

            def fake_execute(config: RunConfig) -> HostResult:
                self.assertEqual(config.name, "native_transition_oracle")
                self.assertEqual(config.use_gdb, False)
                self.assertEqual(config.fixture, fixture_dir / "beginning_of_game.imp")
                self.write_native_bundle(config.run_dir)
                return host_result(config.run_dir)

            original_run = RuntimeRunner.run

            def tracking_run(self_runner, request):
                nonlocal runner_used
                runner_used = True
                return original_run(self_runner, request)

            with patch.object(RuntimeRunner, "run", tracking_run):
                code = run_native_transition(
                    "city_item_order_increase",
                    result_dir=run_dir,
                    execute=fake_execute,
                    fixture_dir=fixture_dir,
                )

            self.assertEqual(code, 0)
            self.assertFalse(runner_used)
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(
                set(result),
                {"name", "seed", "status", "captures_path"},
            )
            self.assertNotIn("evidence_kind", result)
            self.assertNotIn("summary", result)
            self.assertFalse((run_dir / "before.imp").exists())
            self.assertFalse((run_dir / "after.imp").exists())

    def test_copies_save_backed_captures_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            fixture_dir = root / "fixtures"
            fixture_dir.mkdir()
            (fixture_dir / "beginning_of_game.imp").write_bytes(b"fixture")

            def fake_execute(config: RunConfig) -> HostResult:
                self.write_save_backed_bundle(config.run_dir)
                return host_result(config.run_dir)

            code = run_native_transition(
                "city_item_order_increase",
                result_dir=run_dir,
                execute=fake_execute,
                fixture_dir=fixture_dir,
            )

            self.assertEqual(code, 0)
            self.assertEqual((run_dir / "before.imp").read_bytes(), b"before-bytes")
            self.assertEqual((run_dir / "after.imp").read_bytes(), b"after-bytes")

    def test_failed_process_does_not_copy_saves(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            fixture_dir = root / "fixtures"
            fixture_dir.mkdir()
            (fixture_dir / "beginning_of_game.imp").write_bytes(b"fixture")

            def fake_execute(config: RunConfig) -> HostResult:
                self.write_native_bundle(config.run_dir, status="failed")
                return host_result(config.run_dir, classification="crash", exit_code=1)

            code = run_native_transition(
                "city_item_order_increase",
                result_dir=run_dir,
                execute=fake_execute,
                fixture_dir=fixture_dir,
            )

            self.assertEqual(code, 1)
            self.assertFalse((run_dir / "before.imp").exists())
            self.assertFalse((run_dir / "after.imp").exists())


if __name__ == "__main__":
    unittest.main()
