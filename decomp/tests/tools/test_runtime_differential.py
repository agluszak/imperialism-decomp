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
    CHECKPOINT_ELIMINATION_PHASE,
    CHECKPOINT_NAVAL_TIER_EXHAUSTION_PHASE,
    CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX,
    CHECKPOINT_TURN_STATE_AI_REPLAN,
    CHECKPOINT_TURN_STATE_COMBAT_MOVES,
    CHECKPOINT_TURN_STATE_MILITARY_CLEANUP,
    SCHEMAS,
    first_checkpoint_difference,
    normalize_native_combined_map,
    normalize_native_rng_contract,
    normalize_retail_combined_map,
    normalize_retail_rng_contract,
    normalize_retail_strategic_naval_battle_matrix,
    validate_checkpoint,
)
from tools.runtime.retail_checkpoint_differential import (
    _STRATEGIC_NAVAL_BATTLE_MATRIX,
    _normalize_value,
    _scenario_classification,
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
    def test_production_turn_state_schemas_require_semantic_post_state(self) -> None:
        combat = SCHEMAS[CHECKPOINT_TURN_STATE_COMBAT_MOVES].required_paths
        cleanup = SCHEMAS[
            CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
        ].required_paths
        ai_replan = SCHEMAS[CHECKPOINT_TURN_STATE_AI_REPLAN].required_paths
        elimination = SCHEMAS[CHECKPOINT_ELIMINATION_PHASE].required_paths
        newspaper = SCHEMAS["turn_stop_newspaper.resolved"].required_paths

        self.assertIn("dispatched_event", combat)
        self.assertIn("rng.before.crt_rand", combat)
        self.assertIn("rng.after.crt_rand", combat)
        self.assertIn("trade.nations", cleanup)
        self.assertIn("diplomacy.nations", cleanup)
        self.assertIn("missions", cleanup)
        self.assertIn("development", cleanup)
        self.assertIn("military_cleanup.weighted_military", ai_replan)
        self.assertIn("missions", ai_replan)
        self.assertIn("development", ai_replan)
        self.assertIn("rng.after.crt_rand", ai_replan)
        self.assertIn("nation_status", elimination)
        self.assertIn("rng.before.crt_rand", elimination)
        self.assertIn("rng.after.crt_rand", elimination)
        self.assertIn("pending_nations", newspaper)
        self.assertIn("rng.before.crt_rand", newspaper)
        self.assertIn("rng.after.crt_rand", newspaper)

    def test_native_and_retail_normalize_to_one_schema(self) -> None:
        retail = normalize_retail_combined_map(combined_map_fields())
        native = normalize_native_combined_map(
            {
                "status": "passed",
                "captures": {
                    "map_state": {
                        "turn_event": 0x07DD,
                        "root_class": "TMapUberPicture",
                        "active_nation": 6,
                        "economic_turn": 1,
                        "global_map": True,
                        "city_present": True,
                        "production_orders": list(range(16)),
                        "production_flags": [slot % 2 for slot in range(16)],
                        "wrap": 0,
                    }
                },
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

    def test_rng_contract_normalizes_before_and_after_state(self) -> None:
        contract = {
            "before": {
                "crt_rand": 1,
                "map_generation": 2,
                "zone_status": 3,
            },
            "after": {
                "crt_rand": 4,
                "map_generation": 5,
                "zone_status": 6,
            },
        }
        self.assertEqual(
            normalize_native_rng_contract(
                {
                    "captures": {
                        "rng_contract_before": contract["before"],
                        "rng_contract_after": contract["after"],
                    }
                }
            ),
            contract,
        )
        self.assertEqual(
            normalize_retail_rng_contract({"rng_contract": contract}),
            contract,
        )

    def test_rng_post_state_diverges_when_outputs_match(self) -> None:
        retail = normalize_retail_combined_map(combined_map_fields())
        recomp = json.loads(json.dumps(retail))
        retail["rng"] = {
            "before": {
                "crt_rand": 1,
                "map_generation": 2,
                "zone_status": 3,
            },
            "after": {
                "crt_rand": 4,
                "map_generation": 5,
                "zone_status": 6,
            },
        }
        recomp["rng"] = json.loads(json.dumps(retail["rng"]))
        recomp["rng"]["after"]["crt_rand"] = 7
        self.assertEqual(
            first_checkpoint_difference(retail, recomp),
            {
                "path": "$.rng.after.crt_rand",
                "kind": "value_mismatch",
                "retail": 4,
                "recomp": 7,
            },
        )

    def test_equal_rng_contracts_do_not_diverge(self) -> None:
        retail = {
            "rng": {
                "before": {
                    "crt_rand": 1,
                    "map_generation": 2,
                    "zone_status": 3,
                },
                "after": {
                    "crt_rand": 4,
                    "map_generation": 5,
                    "zone_status": 6,
                },
            }
        }
        self.assertIsNone(
            first_checkpoint_difference(retail, json.loads(json.dumps(retail)))
        )

    def test_rng_before_state_is_distinct_from_after_state(self) -> None:
        retail = {
            "rng": {
                "before": {
                    "crt_rand": 1,
                    "map_generation": 2,
                    "zone_status": 3,
                },
                "after": {
                    "crt_rand": 4,
                    "map_generation": 5,
                    "zone_status": 6,
                },
            }
        }
        recomp = json.loads(json.dumps(retail))
        recomp["rng"]["before"]["zone_status"] = 7
        self.assertEqual(
            first_checkpoint_difference(retail, recomp),
            {
                "path": "$.rng.before.zone_status",
                "kind": "value_mismatch",
                "retail": 3,
                "recomp": 7,
            },
        )


class StrategicNavalBattleMatrixTests(unittest.TestCase):
    def test_matrix_covers_semantic_outcomes_and_boundaries(self) -> None:
        self.assertEqual(len(_STRATEGIC_NAVAL_BATTLE_MATRIX), 20)
        self.assertEqual(
            {case["convergence"] for case in _STRATEGIC_NAVAL_BATTLE_MATRIX},
            {
                "only_left_fails",
                "only_right_fails",
                "both_fail",
                "neither_fails",
            },
        )
        self.assertEqual(
            {case["resolution"] for case in _STRATEGIC_NAVAL_BATTLE_MATRIX},
            {
                "tier_exhaustion",
                "left_eliminated",
                "right_eliminated",
                "both_eliminated",
            },
        )
        sides = [
            side
            for case in _STRATEGIC_NAVAL_BATTLE_MATRIX
            for side in (case["left"], case["right"])
        ]
        self.assertGreaterEqual(
            len({ship_type for side in sides for ship_type in side[0]}), 6
        )
        self.assertEqual({side[1] for side in sides}, {0, 1, 2})
        self.assertEqual({side[2] for side in sides}, {1, 100, 500, 1000, 1600})
        self.assertEqual({len(side[0]) for side in sides}, {1, 2, 3, 4})
        self.assertEqual({side[4] for side in sides}, {0, 100, 200, 400})

    def test_matrix_contains_one_sided_tier_exhaustion_cases(self) -> None:
        one_sided = [
            case
            for case in _STRATEGIC_NAVAL_BATTLE_MATRIX
            if case["resolution"] == "tier_exhaustion"
            and case["convergence"] in {"only_left_fails", "only_right_fails"}
        ]
        self.assertGreaterEqual(len(one_sided), 2)
        self.assertEqual(
            {case["convergence"] for case in one_sided},
            {"only_left_fails", "only_right_fails"},
        )

    def test_matrix_scenario_invokes_the_direct_production_driver(self) -> None:
        scenario = load_scenario("strategic_naval_battle_matrix")
        self.assertEqual(scenario.drive, "strategic_naval_battle_matrix")
        self.assertEqual(
            scenario.result_checkpoint_id,
            CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX,
        )
        self.assertEqual(scenario.action_id, "strategic_naval_battle_matrix.run")

    def test_tier_exhaustion_scenario_invokes_the_production_path(self) -> None:
        scenario = load_scenario("military_phase_naval_tier_exhaustion")
        self.assertEqual(
            scenario.result_checkpoint_id,
            CHECKPOINT_NAVAL_TIER_EXHAUSTION_PHASE,
        )
        self.assertEqual(scenario.action_id, "military_phase.run")

    def test_matrix_normalizer_requires_reward_and_ship_state(self) -> None:
        cases = []
        for index in range(20):
            side = {
                "aggression": 0,
                "initial_strength": 100,
                "initial_experience": 5,
                "initial_admiral_experience": 10,
                "defeated": False,
                "admiral_experience": 11,
                "ships": [
                    {
                        "type": 3,
                        "alive": True,
                        "strength": 80,
                        "experience": 8,
                    }
                ],
            }
            cases.append(
                {
                    "case": f"case_{index}",
                    "seed": index,
                    "convergence": "both_fail",
                    "resolution": "tier_exhaustion",
                    "participant": -1,
                    "winner": "draw",
                    "left_defeated": False,
                    "right_defeated": False,
                    "left": side,
                    "right": json.loads(json.dumps(side)),
                }
            )
        observation = normalize_retail_strategic_naval_battle_matrix(
            {"cases": cases}
        )
        validate_checkpoint(observation)
        self.assertEqual(
            observation["cases"][0]["left"]["admiral_experience"], 11
        )
        self.assertEqual(
            observation["cases"][0]["left"]["ships"][0]["experience"], 8
        )


class DifferentialTraceTests(unittest.TestCase):
    def test_scenario_classification_distinguishes_component_probes(self) -> None:
        self.assertEqual(
            _scenario_classification("quarter_gate_off_decade"),
            "component_probe",
        )
        self.assertEqual(
            _scenario_classification("strategic_naval_battle_matrix"),
            "component_probe",
        )
        self.assertEqual(
            _scenario_classification("turn_state_quarter_gate"),
            "production_path",
        )
        self.assertEqual(
            _scenario_classification("military_phase_naval_tier_exhaustion"),
            "production_path",
        )
        self.assertEqual(
            _scenario_classification("turn_state_ai_replan_perturbed"),
            "production_path",
        )
        self.assertEqual(
            _scenario_classification("load_save_to_map"),
            "unclassified",
        )

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
        with patch("tools.runtime.retail_checkpoint_differential.FIXTURE_DIR", root):
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
            patch("tools.runtime.retail_checkpoint_differential.GdbSession", session_type),
            patch("tools.runtime.retail_checkpoint_differential.initialize_wine_prefix", side_effect=initialize),
            patch("tools.runtime.retail_checkpoint_differential.prefix_environment", return_value={}),
            patch("tools.runtime.retail_checkpoint_differential.windows_path", return_value="C:\\fixture.imp"),
            patch("tools.runtime.retail_checkpoint_differential.prepare_game_sandbox", side_effect=prepare),
            patch("tools.runtime.retail_checkpoint_differential.virtual_display", side_effect=display),
            patch("tools.runtime.retail_checkpoint_differential.shut_down_wine_prefix"),
            patch("tools.runtime.retail_checkpoint_differential.direct_call_target_after", return_value=0x1234),
            patch("tools.runtime.retail_checkpoint_differential._capture_fields", side_effect=capture),
            patch(
                "tools.runtime.retail_checkpoint_differential._runtime_rng_state",
                return_value={
                    "crt_rand": 1,
                    "map_generation": 2,
                    "zone_status": 3,
                },
            ),
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

    def test_production_turn_state_scenarios_use_dedicated_checkpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "beginning_of_game.imp"
            fixture.write_bytes(b"fixture")
            with patch(
                "tools.runtime.retail_checkpoint_differential.FIXTURE_DIR",
                root,
            ):
                combat = load_scenario("turn_state_combat_moves")
                cleanup = load_scenario("turn_state_military_cleanup")
                ai_replan = load_scenario("turn_state_ai_replan_perturbed")

        self.assertEqual(
            combat.result_checkpoint_id,
            CHECKPOINT_TURN_STATE_COMBAT_MOVES,
        )
        self.assertEqual(
            cleanup.result_checkpoint_id,
            CHECKPOINT_TURN_STATE_MILITARY_CLEANUP,
        )
        self.assertEqual(
            ai_replan.result_checkpoint_id,
            CHECKPOINT_TURN_STATE_AI_REPLAN,
        )

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
