#!/usr/bin/env python3
"""Contracts for normalized OG/recomp trace comparison."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.debug.session import StopEvent
from tools.runtime.differential import first_divergence, load_scenario, run_binary


class DifferentialTraceTests(unittest.TestCase):
    def test_equal_traces_have_no_divergence(self) -> None:
        trace = [{"seq": 0, "probe": "p", "occurrence": 1, "fields": {"event": 1}}]
        self.assertIsNone(first_divergence(trace, list(trace)))

    def test_first_semantic_mismatch_is_reported(self) -> None:
        original = [
            {"seq": 0, "probe": "p", "occurrence": 1, "fields": {"event": 1}},
            {"seq": 1, "probe": "p", "occurrence": 2, "fields": {"event": 2}},
        ]
        recomp = [
            {"seq": 0, "probe": "p", "occurrence": 1, "fields": {"event": 1}},
            {"seq": 1, "probe": "p", "occurrence": 2, "fields": {"event": 3}},
        ]
        mismatch = first_divergence(original, recomp)
        self.assertEqual(
            mismatch["semantic_key"], {"probe": "p", "occurrence": 2}
        )
        self.assertEqual(mismatch["last_equal_checkpoint"], {"probe": "p", "occurrence": 1})
        self.assertEqual(mismatch["original"]["fields"]["event"], 2)
        self.assertEqual(mismatch["recomp"]["fields"]["event"], 3)

    def test_alignment_reports_missing_semantic_occurrence(self) -> None:
        original = [
            {"probe": "p", "occurrence": 1, "fields": {"event": 1}},
            {"probe": "p", "occurrence": 2, "fields": {"event": 2}},
        ]
        recomp = [{"probe": "p", "occurrence": 2, "fields": {"event": 2}}]
        mismatch = first_divergence(original, recomp)
        self.assertEqual(mismatch["kind"], "missing_recomp")
        self.assertEqual(mismatch["semantic_key"], {"probe": "p", "occurrence": 1})


class FakeDifferentialSession:
    instances = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.breakpoint = 0
        self.current_event = 0
        self.current_payload = 0
        self.stops = [
            ("1", 0, 0),
            ("2", 0x05DC, 0),
            ("3", 0, 0),
            ("2", 0x07DD, 4),
        ]
        type(self).instances.append(self)

    def start(self, auto_continue: bool = True) -> None:
        del auto_continue

    def set_breakpoint(self, _address: int) -> str:
        self.breakpoint += 1
        return str(self.breakpoint)

    def wait_for_stop(self, _timeout: float) -> StopEvent:
        number, self.current_event, self.current_payload = self.stops.pop(0)
        return StopEvent("breakpoint-hit", None, number, f"breakpoint {number}")

    def evaluate(self, expression: str) -> str:
        values = {
            "$ecx": 0x1000,
            "*(unsigned int*)($esp+4)": 0x2000,
            "*(int*)0x00002010": 1,
            "*(unsigned int*)0x00002014": 0x3000,
            "*(unsigned int*)$esp": 0x4000,
            "*(unsigned int*)0x00001000": 0x6000,
            "*(unsigned int*)0x00006084": 0x7000,
            "$esp": 0x5000,
            "*(short*)($esp+4)": self.current_event,
            "*(int*)($esp+8)": self.current_payload,
        }
        return hex(values[expression])

    def assign(self, _expression: str, _value: int | str) -> None:
        pass

    def continue_inferior(self) -> None:
        pass

    def delete_breakpoint(self, _number: str) -> None:
        pass

    def interrupt_and_capture(self, _label: str) -> None:
        pass

    def close(self) -> None:
        pass


class BrokenDifferentialSession(FakeDifferentialSession):
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        super().__init__(*_args, **_kwargs)
        self.stops = self.stops[:2]


class DifferentialRunTests(unittest.TestCase):
    def make_scenario(self, root: Path):
        fixture = root / "beginning_of_game.imp"
        fixture.write_bytes(b"fixture")
        with patch("tools.runtime.differential.FIXTURE_DIR", root):
            return load_scenario("load_save_to_map")

    def run_with_session(self, root: Path, session_type: type[FakeDifferentialSession]):
        executable = root / "Imperialism.exe"
        executable.write_bytes(b"binary")
        scenario = self.make_scenario(root)
        run_dir = root / "run"
        run_dir.mkdir()

        def initialize(prefix: Path, _environment: dict[str, str]) -> None:
            (prefix / "drive_c").mkdir(parents=True)

        patches = (
            patch("tools.runtime.differential.GdbSession", session_type),
            patch("tools.runtime.differential.initialize_wine_prefix", side_effect=initialize),
            patch("tools.runtime.differential.prefix_environment", return_value={}),
            patch("tools.runtime.differential.windows_path", return_value="C:\\fixture.imp"),
            patch("tools.runtime.differential.retail_game_dir", return_value=root),
            patch("tools.runtime.differential.shut_down_wine_prefix"),
            patch("tools.runtime.differential.direct_call_target_after", return_value=0x1234),
        )
        return scenario, executable, run_dir, patches

    def test_fake_session_executes_typed_multi_field_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario, executable, run_dir, patches = self.run_with_session(
                root, FakeDifferentialSession
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                trace = run_binary(
                    scenario,
                    "recomp",
                    executable,
                    {"turn_event.dispatch": 0x5555},
                    {"initialization_owner": 1, "before_shell_callee": 2},
                    run_dir,
                    30.0,
                )

            self.assertEqual(trace.metadata["status"], "completed")
            self.assertEqual(
                trace.records[-1]["fields"], {"event": 0x07DD, "payload": 4}
            )
            lines = (run_dir / "recomp" / "trace.ndjson").read_text(
                encoding="utf-8"
            ).splitlines()
            metadata = json.loads(lines[0])
            self.assertEqual(metadata["type"], "trace_metadata")
            self.assertEqual(metadata["binary"]["sha256"], trace.metadata["binary"]["sha256"])

    def test_partial_trace_is_persisted_when_session_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario, executable, run_dir, patches = self.run_with_session(
                root, BrokenDifferentialSession
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                with self.assertRaises(IndexError):
                    run_binary(
                        scenario,
                        "original",
                        executable,
                        {"turn_event.dispatch": 0x5555},
                        {"initialization_owner": 1, "before_shell_callee": 2},
                        run_dir,
                        30.0,
                    )
            lines = (run_dir / "original" / "trace.ndjson").read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(json.loads(lines[0])["status"], "partial")
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
