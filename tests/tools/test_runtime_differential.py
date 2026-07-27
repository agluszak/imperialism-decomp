#!/usr/bin/env python3
"""Contracts for normalized OG/recomp trace comparison."""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.runtime.debug.session import StopEvent
from tools.runtime.checkpoints import (
    CHECKPOINT_COMBINED_MAP_READY,
    first_checkpoint_difference,
    normalize_native_combined_map,
    normalize_retail_combined_map,
    validate_checkpoint,
)
from tools.runtime.differential import (
    _normalize_value,
    first_divergence,
    load_scenario,
    run_binary,
)


def combined_map_fields() -> dict:
    return {
        "turn_event": 0x07DD,
        "combined_map_view_present": True,
        "active_nation": 6,
        "economic_turn": 1,
        "map_present": True,
        "map_wrap": 0,
        "city_present": True,
        **{f"production_order_{slot:02d}": slot for slot in range(16)},
        **{f"production_flag_{slot:02d}": slot % 2 for slot in range(16)},
    }


class CheckpointSchemaTests(unittest.TestCase):
    def test_native_and_retail_normalize_to_one_schema(self) -> None:
        retail = normalize_retail_combined_map(combined_map_fields())
        native = normalize_native_combined_map(
            {
                "status": "passed",
                "state": {
                    "turn_event": 0x07DD,
                    "root_class": "TMapUberPicture",
                    "active_nation": 6,
                    "economic_turn": 1,
                    "global_map": True,
                    "city_present": True,
                    "production_orders": list(range(16)),
                    "production_flags": [slot % 2 for slot in range(16)],
                },
                "map_state": {"wrap": 0},
            }
        )
        validate_checkpoint(retail)
        validate_checkpoint(native)
        self.assertEqual(retail["checkpoint_id"], CHECKPOINT_COMBINED_MAP_READY)
        self.assertIsNone(first_checkpoint_difference(retail, native))

    def test_checkpoint_difference_reports_nested_field_path(self) -> None:
        retail = normalize_retail_combined_map(combined_map_fields())
        recomp = json.loads(json.dumps(retail))
        recomp["city_orders"]["production_orders"][7] = 99
        self.assertEqual(
            first_checkpoint_difference(retail, recomp),
            {
                "path": "$.city_orders.production_orders[7]",
                "kind": "value_mismatch",
                "retail": 7,
                "recomp": 99,
            },
        )


class DifferentialTraceTests(unittest.TestCase):
    def test_gdb_character_rendering_normalizes_to_integer(self) -> None:
        self.assertEqual(_normalize_value("0 '\\000'", "int"), 0)

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
            ("2", 0x11F8, 0),
            ("3", 0, 0),
            ("2", 0x07DD, 4),
            ("4", 0, 0),
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

        def prepare(run_dir: Path, source: Path, fixture: Path):
            game_dir = run_dir / "game"
            game_dir.mkdir()
            sandbox = game_dir / "Imperialism.exe"
            sandbox.write_bytes(source.read_bytes())
            fixture_dir = run_dir / "fixtures"
            fixture_dir.mkdir()
            staged_fixture = fixture_dir / fixture.name
            staged_fixture.write_bytes(fixture.read_bytes())
            return game_dir, staged_fixture, "asset-manifest"

        @contextmanager
        def display(environment: dict[str, str], _log_path: Path):
            environment["DISPLAY"] = ":99"
            yield ":99"

        def capture(session: FakeDifferentialSession, probe):
            if probe.probe_id == CHECKPOINT_COMBINED_MAP_READY:
                return combined_map_fields()
            return {"event": session.current_event, "payload": session.current_payload}

        patches = (
            patch("tools.runtime.differential.GdbSession", session_type),
            patch("tools.runtime.differential.initialize_wine_prefix", side_effect=initialize),
            patch("tools.runtime.differential.prefix_environment", return_value={}),
            patch("tools.runtime.differential.windows_path", return_value="C:\\fixture.imp"),
            patch("tools.runtime.differential.prepare_game_sandbox", side_effect=prepare),
            patch("tools.runtime.differential.virtual_display", side_effect=display),
            patch("tools.runtime.differential.shut_down_wine_prefix"),
            patch("tools.runtime.differential.direct_call_target_after", return_value=0x1234),
            patch("tools.runtime.differential._capture_fields", side_effect=capture),
        )
        return scenario, executable, run_dir, patches

    def test_fake_session_executes_typed_multi_field_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario, executable, run_dir, patches = self.run_with_session(
                root, FakeDifferentialSession
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
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
            self.assertEqual(trace.records[-1]["probe"], CHECKPOINT_COMBINED_MAP_READY)
            self.assertEqual(trace.records[-1]["fields"], combined_map_fields())
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
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
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
