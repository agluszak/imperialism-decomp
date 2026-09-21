"""Compare a native recomp checkpoint with a narrow retail GDB observation.

This is the retail-vs-recomp GDB checkpoint runner. It is separate from the
C++→Rust process-isolated differential in the Rust testkit.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import struct
import time

from tools.runtime.checkpoints import (
    CHECKPOINT_CITY_TRANSPORT_PHASE,
    CHECKPOINT_CIVILIANS_PHASE,
    CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE,
    CHECKPOINT_DIPLOMACY_PHASE,
    CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE,
    CHECKPOINT_SECOND_TURN_TRADE_PHASE,
    CHECKPOINT_MILITARY_PHASE,
    CHECKPOINT_NAVAL_ENCOUNTER_PHASE,
    CHECKPOINT_NAVAL_ESCALATION_PHASE,
    CHECKPOINT_LAND_COMBAT_PHASE,
    CHECKPOINT_LAND_INTERACTIVE_PHASE,
    CHECKPOINT_LAND_RETREAT_PHASE,
    CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
    CHECKPOINT_RECOMPUTE_METRICS,
    CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
    CHECKPOINT_SECOND_TURN_MILITARY_PHASE,
    CHECKPOINT_SECOND_TURN_SEQUENCE,
    CHECKPOINT_TRADE_PHASE,
    SCHEMAS,
    first_checkpoint_difference,
    normalize_native_city_transport_phase,
    normalize_native_civilians_phase,
    normalize_native_military_cleanup,
    normalize_native_recompute_metrics,
    normalize_native_military_phase,
    normalize_native_second_turn_sequence,
    normalize_native_combined_map,
    normalize_native_diplomacy_phase,
    normalize_native_trade_phase,
    normalize_retail_city_transport_phase,
    normalize_retail_civilians_phase,
    normalize_retail_combined_map,
    normalize_retail_military_cleanup,
    normalize_retail_recompute_metrics,
    normalize_retail_military_phase,
    normalize_retail_second_turn_sequence,
    normalize_retail_diplomacy_phase,
    normalize_retail_trade_phase,
    validate_checkpoint,
)
from tools.runtime.debug.binary import direct_call_target_after
from tools.runtime.debug.mi_process import DebuggerTransportError
from tools.runtime.debug.session import GdbSession, is_terminal_stop
from tools.runtime.display import virtual_display
from tools.runtime.runner import RunRequest, RuntimeRunner
from tools.runtime.wine import (
    file_identity,
    initialize_wine_prefix,
    prefix_environment,
    prepare_game_sandbox,
    shut_down_wine_prefix,
    windows_path,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
FIXTURE_DIR = REPO_ROOT.parent / "fixtures" / "retail"
RESULT_DIR = BUILD_DIR / "differential-results"


@dataclass(frozen=True)
class Probe:
    probe_id: str
    original_address: int
    fields: dict[str, "FieldCapture"]


@dataclass(frozen=True)
class FieldCapture:
    expression: str
    normalize: str = "int"


@dataclass(frozen=True)
class ProbeWait:
    probe: str
    field: str
    equals: int


@dataclass(frozen=True)
class DeferredShellAction:
    owner_address: int
    after_call_to: int
    replay_after: ProbeWait
    rewrite_probe: str
    rewrite_field: str
    rewrite_from: int
    rewrite_to: int
    rewrite_expression: str
    rewrite_action_id: str


@dataclass(frozen=True)
class Checkpoint:
    probe: str
    field: str
    equals: int
    checkpoint_id: str
    fields: dict[str, FieldCapture]


@dataclass(frozen=True)
class Scenario:
    name: str
    native_test: str
    action_id: str
    fixture: Path
    probes: tuple[Probe, ...]
    terminal_checkpoint: Checkpoint
    timeout_seconds: float
    start_action: DeferredShellAction
    drive: str = ""
    result_checkpoint_id: str = ""


@dataclass(frozen=True)
class Trace:
    metadata: dict
    records: list[dict]


def _load_save_to_map_scenario(fixture: Path) -> Scenario:
    """Embedded retail-vs-recomp GDB checkpoint scenario."""
    production_orders = {
            "production_order_00": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1dc)', 's16'),
            "production_order_01": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1de)', 's16'),
            "production_order_02": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e0)', 's16'),
            "production_order_03": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e2)', 's16'),
            "production_order_04": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e4)', 's16'),
            "production_order_05": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e6)', 's16'),
            "production_order_06": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e8)', 's16'),
            "production_order_07": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1ea)', 's16'),
            "production_order_08": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1ec)', 's16'),
            "production_order_09": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1ee)', 's16'),
            "production_order_10": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f0)', 's16'),
            "production_order_11": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f2)', 's16'),
            "production_order_12": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f4)', 's16'),
            "production_order_13": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f6)', 's16'),
            "production_order_14": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f8)', 's16'),
            "production_order_15": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1fa)', 's16'),
    }
    production_flags = {
            "production_flag_00": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21c)', 'int'),
            "production_flag_01": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21d)', 'int'),
            "production_flag_02": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21e)', 'int'),
            "production_flag_03": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21f)', 'int'),
            "production_flag_04": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x220)', 'int'),
            "production_flag_05": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x221)', 'int'),
            "production_flag_06": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x222)', 'int'),
            "production_flag_07": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x223)', 'int'),
            "production_flag_08": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x224)', 'int'),
            "production_flag_09": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x225)', 'int'),
            "production_flag_10": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x226)', 'int'),
            "production_flag_11": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x227)', 'int'),
            "production_flag_12": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x228)', 'int'),
            "production_flag_13": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x229)', 'int'),
            "production_flag_14": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x22a)', 'int'),
            "production_flag_15": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x22b)', 'int'),
    }
    checkpoint_fields = {
            "turn_event": FieldCapture('*(short*)(*(unsigned int*)0x006a21bc + 4)', 'u16'),
            "combined_map_view_present": FieldCapture('*(unsigned int*)(*(unsigned int*)0x006a21bc + 0xf0)', 'bool'),
            "active_nation": FieldCapture('*(short*)(*(unsigned int*)0x006a20f8 + 0x2e)', 's16'),
            "economic_turn": FieldCapture('*(short*)(*(unsigned int*)0x006a20f8 + 0x2c)', 's16'),
            "map_present": FieldCapture('*(unsigned int*)0x006a43d4', 'bool'),
            "map_wrap": FieldCapture('*(char*)(*(unsigned int*)0x006a43d4 + 0x20)', 'int'),
            "city_present": FieldCapture('*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894)', 'bool'),
    }
    checkpoint_fields.update(production_orders)
    checkpoint_fields.update(production_flags)
    return Scenario(
        name="load_save_to_map",
        native_test="load_saved_game",
        action_id="combined_map.enter",
        fixture=fixture,
        probes=(
            Probe(
                probe_id="turn_event.dispatch",
                original_address=0x005d7240,
                fields={
                    "event": FieldCapture("*(short*)($esp+4)", "u16"),
                    "payload": FieldCapture("*(int*)($esp+8)", "u32"),
                },
            ),
        ),
        terminal_checkpoint=Checkpoint(
            probe="turn_event.dispatch",
            field="event",
            equals=0x07dd,
            checkpoint_id="combined_map.ready",
            fields=checkpoint_fields,
        ),
        timeout_seconds=90.0,
        start_action=DeferredShellAction(
            owner_address=0x00412dc0,
            after_call_to=0x00415760,
            replay_after=ProbeWait(probe="turn_event.dispatch", field="event", equals=0x11f8),
            rewrite_probe="turn_event.dispatch",
            rewrite_field="event",
            rewrite_from=0x11f8,
            rewrite_to=0x05dc,
            rewrite_expression="*(short*)($esp+4)",
            rewrite_action_id="opening_cinematic.skip_to_main_menu",
        ),
    )


def _diplomacy_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native diplomacy transition under GDB."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="diplomacy_phase",
        native_test="diplomacy_phase_applies_grant_and_consulate",
        action_id="diplomacy_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="diplomacy_phase",
        result_checkpoint_id=CHECKPOINT_DIPLOMACY_PHASE,
    )


def _trade_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native trade transition under GDB."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="trade_phase",
        native_test="trade_phase",
        action_id="trade_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="trade_phase",
        result_checkpoint_id=CHECKPOINT_TRADE_PHASE,
    )


def _city_transport_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native city+transport transition."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="city_transport_phase",
        native_test="city_and_transport_phase",
        action_id="city_transport_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="city_transport_phase",
        result_checkpoint_id=CHECKPOINT_CITY_TRANSPORT_PHASE,
    )


def _civilians_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native civilians transition."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="civilians_phase",
        native_test="civilians_phase",
        action_id="civilians_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="civilians_phase",
        result_checkpoint_id=CHECKPOINT_CIVILIANS_PHASE,
    )


def _military_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native military transition."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="military_phase",
        native_test="military_phase",
        action_id="military_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="military_phase",
        result_checkpoint_id=CHECKPOINT_MILITARY_PHASE,
    )


def _military_phase_naval_encounter_scenario(
    fixture: Path, name: str = "military_phase_naval_encounter"
) -> Scenario:
    """Reach the loaded map, then drive the naval-encounter transition."""
    base = _load_save_to_map_scenario(fixture)
    trace_fields = {"receiver": FieldCapture("$ecx", "u32")}
    trace_probes = tuple(
        Probe(probe_id=f"navy_trace.{name}", original_address=address,
              fields=trace_fields)
        for name, address in (
            ("try_to_spot", 0x555720),
            ("encounter", 0x555420),
            ("resolve_encounter", 0x555920),
            ("battle_with", 0x555D10),
            ("resolve_strategic_battle", 0x55A780),
            ("sink_or_swim", 0x553FE0),
            ("task_force_free", 0x552930),
            ("ship_free", 0x54F640),
            ("remove_stragglers", 0x555090),
            ("make_sure_orders", 0x557560),
        )
    )
    return Scenario(
        name=name,
        native_test=name,
        action_id="military_phase.run",
        fixture=fixture,
        probes=base.probes + trace_probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive=name,
        result_checkpoint_id=CHECKPOINT_NAVAL_ESCALATION_PHASE
        if name == "military_phase_naval_escalation"
        else CHECKPOINT_NAVAL_ENCOUNTER_PHASE,
    )


def _military_phase_land_combat_scenario(
    fixture: Path, name: str = "military_phase_land_combat"
) -> Scenario:
    """Reach the loaded map, then drive the land-combat transition."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name=name,
        native_test=name,
        action_id="military_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive=name,
        result_checkpoint_id={
            "military_phase_land_combat": CHECKPOINT_LAND_COMBAT_PHASE,
            "military_phase_land_interactive": CHECKPOINT_LAND_INTERACTIVE_PHASE,
            "military_phase_land_retreat": CHECKPOINT_LAND_RETREAT_PHASE,
        }[name],
    )


def load_scenario(name: str) -> Scenario:
    fixture_root = Path(os.environ.get("IMPERIALISM_SAVE_FIXTURES", FIXTURE_DIR))
    fixture = fixture_root / "beginning_of_game.imp"
    if not fixture.is_file():
        raise SystemExit(f"missing differential fixture {fixture}")
    if name == "load_save_to_map":
        scenario = _load_save_to_map_scenario(fixture)
    elif name == "second_turn_civilians_phase":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="civilians_phase.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE,
        )
    elif name == "second_turn_trade_phase":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="trade_phase.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SECOND_TURN_TRADE_PHASE,
        )
    elif name == "second_turn_diplomacy_phase":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="diplomacy_phase.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE,
        )
    elif name == "diplomacy_phase":
        scenario = _diplomacy_phase_scenario(fixture)
    elif name == "trade_phase":
        scenario = _trade_phase_scenario(fixture)
    elif name == "city_transport_phase":
        scenario = _city_transport_phase_scenario(fixture)
    elif name == "civilians_phase":
        scenario = _civilians_phase_scenario(fixture)
    elif name == "military_phase":
        scenario = _military_phase_scenario(fixture)
    elif name in ("military_phase_naval_encounter",
                  "military_phase_naval_escalation"):
        scenario = _military_phase_naval_encounter_scenario(fixture, name)
    elif name in ("military_phase_land_combat",
                  "military_phase_land_interactive",
                  "military_phase_land_retreat"):
        scenario = _military_phase_land_combat_scenario(fixture, name)
    elif name == "second_turn_sequence":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="second_turn_sequence.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SECOND_TURN_SEQUENCE,
        )
    elif name == "second_turn_military_phase":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="military_phase.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_PHASE,
        )
    elif name == "second_turn_military_cleanup":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="second_turn_military_cleanup.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
        )
    elif name == "recompute_nation_order_priority_metrics":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="recompute_nation_order_priority_metrics.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_RECOMPUTE_METRICS,
        )
    elif name == "military_phase_ships_without_orders":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id="military_phase.run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
        )
    else:
        raise SystemExit(f"unknown retail checkpoint differential scenario {name!r}")
    checkpoint_id = scenario.result_checkpoint_id or scenario.terminal_checkpoint.checkpoint_id
    schema = SCHEMAS.get(checkpoint_id)
    if schema is None:
        raise SystemExit(f"unknown differential checkpoint {checkpoint_id}")
    if scenario.action_id != schema.action_id:
        raise SystemExit(
            f"checkpoint {schema.checkpoint_id!r} requires action {schema.action_id!r}"
        )
    if scenario.native_test != schema.native_test:
        raise SystemExit(
            f"checkpoint {schema.checkpoint_id!r} requires native test {schema.native_test!r}"
        )
    return scenario

def first_divergence(original: list[dict], recomp: list[dict]) -> dict | None:
    def key(record: dict) -> tuple[str, int]:
        return str(record["probe"]), int(record["occurrence"])

    original_by_key = {key(record): record for record in original}
    recomp_by_key = {key(record): record for record in recomp}
    keys = list(original_by_key)
    keys.extend(key_value for key_value in recomp_by_key if key_value not in original_by_key)
    last_equal: dict | None = None
    for probe, occurrence in keys:
        semantic_key = {"probe": probe, "occurrence": occurrence}
        left = original_by_key.get((probe, occurrence))
        right = recomp_by_key.get((probe, occurrence))
        left_fields = left.get("fields") if left is not None else None
        right_fields = right.get("fields") if right is not None else None
        if left_fields != right_fields:
            if left is None:
                mismatch_kind = "missing_original"
            elif right is None:
                mismatch_kind = "missing_recomp"
            else:
                mismatch_kind = "field_mismatch"
            return {
                "semantic_key": semantic_key,
                "kind": mismatch_kind,
                "original": left,
                "recomp": right,
                "last_equal_checkpoint": last_equal,
            }
        last_equal = semantic_key
    return None


def _write_trace(path: Path, metadata: dict, records: list[dict]) -> None:
    path.write_text(
        json.dumps({"type": "trace_metadata", **metadata}, sort_keys=True)
        + "\n"
        + "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _normalize_value(raw: str, normalization: str) -> int | str:
    numeric_text = raw if normalization == "string" else raw.split(maxsplit=1)[0]
    try:
        value = int(numeric_text, 0)
    except ValueError:
        return raw.strip() if normalization == "string" else raw
    if normalization == "u16":
        return value & 0xFFFF
    if normalization == "s16":
        value &= 0xFFFF
        return value - 0x10000 if value & 0x8000 else value
    if normalization == "u32":
        return value & 0xFFFFFFFF
    if normalization == "bool":
        return value != 0
    if normalization not in {"int", "pointer"}:
        raise ValueError(f"unknown differential field normalization {normalization!r}")
    return value


def _capture_fields(session: GdbSession, probe: Probe) -> dict[str, int | str]:
    fields: dict[str, int | str] = {}
    for name, capture in probe.fields.items():
        fields[name] = _normalize_value(
            session.evaluate(capture.expression), capture.normalize
        )
    return fields


# --- diplomacy_phase retail drive -------------------------------------------------
# Mirrors NativeDiplomacyCases.cpp RunDiplomacyPhase: seed eligibility, a one-time
# grant, and a build-consulate policy on the active nation, then invoke
# TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn plus per-nation
# TGreatPower::ReplyToDiplomacyOffers through inferior calls.

_SIM_MGR = 0x006A20F8
_NATION_STATES = 0x006A4370
_DIPLOMACY_MGR = 0x006A43D0
_TERRAIN_TABLE = 0x006A4310
_SET_GRANT_ENTRY = 0x004DE340
_APPLY_DIPLOMACY_TURN = 0x004F01E0
_REPLY_TO_OFFERS = 0x004DF5F0
_MAJOR_NATION_COUNT = 7
_NATION_SLOT_COUNT = 23
_MINOR_NATION_FIRST_SLOT = 7
_DIPLOMACY_PROPOSAL_BUILD_CONSULATE = 0x133


def _eval_int(session: GdbSession, expression: str) -> int:
    return int(session.evaluate(expression).split(maxsplit=1)[0], 0)


def _wait_for_injected_return(
    session: GdbSession,
    breakpoint_number: str,
    deadline: float,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    while time.monotonic() < deadline:
        stop = session.wait_for_stop(min(1.0, deadline - time.monotonic()))
        if stop is None:
            if session.process.poll() is not None:
                raise RuntimeError("debugged game exited before the injected call returned")
            continue
        if is_terminal_stop(stop):
            raise RuntimeError("debugged game exited before the injected call returned")
        if stop.reason == "breakpoint-hit" and stop.breakpoint_number == breakpoint_number:
            return
        role = breakpoint_roles.get(stop.breakpoint_number or "")
        if role is not None and role[0] == "probe" and role[1] is not None:
            probe = role[1]
            occurrence = occurrences.get(probe.probe_id, 0) + 1
            occurrences[probe.probe_id] = occurrence
            records.append(
                {
                    "type": "checkpoint",
                    "seq": len(records),
                    "probe": probe.probe_id,
                    "occurrence": occurrence,
                    "fields": _capture_fields(session, probe),
                }
            )
            session.continue_inferior()
            continue
        session.capture_stop(
            f"unexpected-injected-{stop.signal_name or stop.reason}", stop
        )
        raise RuntimeError(
            f"debugged game stopped unexpectedly during injected call: "
            f"{stop.signal_name or stop.reason}"
        )
    session.interrupt_and_capture("injected-call-timeout")
    raise RuntimeError("timed out waiting for injected call to return")


def _invoke_thiscall(
    session: GdbSession,
    address: int,
    receiver: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    args: tuple[int, ...] = (),
) -> int:
    stack = _eval_int(session, "$esp")
    return_address = _eval_int(session, "$eip")
    return_breakpoint = session.set_breakpoint(return_address)
    try:
        frame = stack - 4 * (len(args) + 1)
        session.assign(f"*(unsigned int*)0x{frame:08x}", return_address)
        for index, argument in enumerate(args):
            session.assign(
                f"*(int*)0x{frame + 4 + 4 * index:08x}", argument
            )
        session.assign("$esp", frame)
        session.assign("$ecx", receiver)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_injected_return(
            session,
            return_breakpoint,
            time.monotonic() + 30.0,
            records,
            occurrences,
            breakpoint_roles,
        )
        result = _eval_int(session, "$eax")
        session.assign("$esp", stack)
        return result
    finally:
        session.delete_breakpoint(return_breakpoint)


def _nation_pointer(session: GdbSession, slot: int) -> int:
    return _eval_int(
        session, f"*(unsigned int*)0x{_NATION_STATES + 4 * slot:08x}"
    )


def _drive_diplomacy_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    active_slot = _eval_int(session, f"*(short*)0x{sim_mgr + 0x2E:08x}")
    active_nation = _nation_pointer(session, active_slot)
    diplomacy_mgr = _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")
    if active_nation == 0 or diplomacy_mgr == 0:
        raise RuntimeError("retail loaded player has no diplomacy state")
    if (
        _eval_int(
            session,
            f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * _MINOR_NATION_FIRST_SLOT:08x}",
        )
        == 0
    ):
        raise RuntimeError("retail fixture has no first minor nation")

    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            session.assign(f"*(unsigned char*)0x{nation + 0xA0:08x}", 1)

    grant_target = (active_slot + 1) % _MAJOR_NATION_COUNT
    accepted = _invoke_thiscall(
        session,
        _SET_GRANT_ENTRY,
        active_nation,
        records,
        occurrences,
        breakpoint_roles,
        args=(grant_target, 1000),
    )
    if accepted & 0xFF == 0:
        raise RuntimeError("retail rejected the seeded diplomacy grant")
    session.assign(
        f"*(short*)0x{active_nation + 0xB2 + 2 * _MINOR_NATION_FIRST_SLOT:08x}",
        _DIPLOMACY_PROPOSAL_BUILD_CONSULATE,
    )

    _invoke_thiscall(
        session,
        _APPLY_DIPLOMACY_TURN,
        diplomacy_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _REPLY_TO_OFFERS,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )


# --- trade_phase retail drive ---------------------------------------------------
# Mirrors NativeTradeCases.cpp RunTradePhaseCase / ExecuteDoTradeWithoutPhaseAdvance:
# seed merchant capacity + stocks, run the market pipeline, drain ranked deals with
# the human auto-accept substitution, then fold offer cells without StartNextPhase.

_TRADE_MGR = 0x006A43CC
_TRADE_DEAL_CATEGORY_ORDER = 0x0066D810
_INITIALIZE_DEAL_BOOK = 0x004DD310
_CLEAR_TRADE_OFFERS = 0x004DDF90
_RESET_NATION_METRIC_ROWS = 0x005B7FC0
_RUN_NATION_UPDATE_PASSES = 0x005B97C0
_SET_MINORS_TRADE_BIDS = 0x005B9890
_TALLY_TRADE_BIDS = 0x005B98D0
_CALCULATE_NEW_WORLD_PRICES = 0x005B8AA0
_CALCULATE_DEAL_ORDER = 0x005B8080
_SET_DEAL_RESULTS = 0x005B94D0
# TCountry vtable slots (index * 4).
_VT_GET_AMT_UNSOLD = 0x1C * 4
_VT_GET_MERCHANT_CAPACITY = 0x1D * 4
_VT_STILL_BUYING_ITEM = 0x21 * 4
_VT_REPLY_TO_TRADE_OFFER = 0x22 * 4
# Retail CRT srand (cdecl): seeds the thread-local rand() stream that minor bids
# and AI offer replies consume. Must match the srand() call in RunTradePhaseCase.
_SRAND = 0x005E83E0
_TRADE_CATEGORY_COUNT = 0x11
_TRADE_ROW_STRIDE = 0xA0
_TRADE_ROW_BASE = 4  # categoryRows[0] starts at TTradeMgr + 0x04
_TRADE_RANK_LISTS = 0xAA8


def _invoke_virtual(
    session: GdbSession,
    receiver: int,
    slot_offset: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    args: tuple[int, ...] = (),
) -> int:
    vtable = _eval_int(session, f"*(unsigned int*)0x{receiver:08x}")
    address = _eval_int(session, f"*(unsigned int*)0x{vtable + slot_offset:08x}")
    return _invoke_thiscall(
        session, address, receiver, records, occurrences, breakpoint_roles, args
    )


def _s16(session: GdbSession, address: int) -> int:
    value = _eval_int(session, f"*(short*)0x{address:08x}") & 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _deal_entry(session: GdbSession, deal_list: int, ordinal: int) -> int:
    data = _eval_int(session, f"*(unsigned int*)0x{deal_list + 4:08x}")
    if data == 0 or ordinal < 1:
        return 0
    return _eval_int(
        session, f"*(unsigned int*)0x{data + 4 * (ordinal - 1):08x}"
    )


def _deal_list_size(session: GdbSession, deal_list: int) -> int:
    if deal_list == 0:
        return 0
    return _eval_int(session, f"*(int*)0x{deal_list + 8:08x}")


def _drive_trade_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    stages: "dict[str, object] | None" = None,
    economic_turn: int | None = None,
) -> None:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    if economic_turn is not None:
        session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", economic_turn)
    trade_mgr = _eval_int(session, f"*(unsigned int*)0x{_TRADE_MGR:08x}")
    active_slot = _s16(session, sim_mgr + 0x2E)
    active_nation = _nation_pointer(session, active_slot)
    if trade_mgr == 0 or active_nation == 0:
        raise RuntimeError("retail loaded game has no trade market")
    if (
        _eval_int(session, f"*(unsigned int*)0x{active_nation + 0x894:08x}") == 0
        or _eval_int(session, f"*(unsigned char*)0x{active_nation + 0xA0:08x}") == 0
    ):
        raise RuntimeError("retail active nation is not a human great power")

    stock_seed = {0: 8, 1: 8, 2: 12, 3: 10, 4: 10, 5: 4, 6: 6,
                  7: 16, 13: 10, 14: 8, 15: 8, 16: 6}
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        city = _eval_int(session, f"*(unsigned int*)0x{nation + 0x894:08x}")
        if city == 0:
            continue
        session.write_memory(city + 0x5C, b"\x00" * 28)
        for index, value in ((1, 2), (5, 1), (10, 1)):
            session.assign(f"*(short*)0x{city + 0x5C + 2 * index:08x}", value)
        for index, value in stock_seed.items():
            session.assign(
                f"*(short*)0x{city + 0xB6 + 2 * index:08x}", value
            )
        session.assign(f"*(int*)0x{nation + 0x10:08x}", 20000)

    session.write_memory(active_nation + 0x250, b"\x00" * 46)
    session.write_memory(active_nation + 0x1C6, b"\x00" * 46)
    session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 13:08x}", -1)
    session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 2:08x}", 5)

    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )

    for slot in range(_MAJOR_NATION_COUNT - 1, -1, -1):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _INITIALIZE_DEAL_BOOK,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )

    stage_names = (
        "reset",
        "nation_updates",
        "minors_bids",
        "tally_bids",
        "new_world_prices",
        "deal_order",
    )
    for stage_name, address in zip(
        stage_names,
        (
            _RESET_NATION_METRIC_ROWS,
            _RUN_NATION_UPDATE_PASSES,
            _SET_MINORS_TRADE_BIDS,
            _TALLY_TRADE_BIDS,
            _CALCULATE_NEW_WORLD_PRICES,
            _CALCULATE_DEAL_ORDER,
        ),
    ):
        _invoke_thiscall(
            session, address, trade_mgr, records, occurrences, breakpoint_roles
        )
        if stages is not None:
            stages[stage_name] = _capture_trade_phase(session)["market_rows"]

    row0 = trade_mgr + _TRADE_ROW_BASE
    session.assign(f"*(short*)0x{row0 + 2:08x}", 1)
    session.assign(f"*(short*)0x{row0:08x}", 0)
    next_index = 0
    while True:
        index = _s16(session, row0)
        dispatch = _s16(session, _TRADE_DEAL_CATEGORY_ORDER + 2 * index)
        deal_list = _eval_int(
            session, f"*(unsigned int*)0x{trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch:08x}"
        )
        if _deal_list_size(session, deal_list) != 0:
            break
        next_index = _s16(session, row0) + 1
        session.assign(f"*(short*)0x{row0:08x}", next_index)
        if next_index >= 0x11:
            break

    while _s16(session, row0) <= 0x10:
        index = _s16(session, row0)
        dispatch = _s16(session, _TRADE_DEAL_CATEGORY_ORDER + 2 * index)
        deal_list = _eval_int(
            session, f"*(unsigned int*)0x{trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch:08x}"
        )
        ordinal = _s16(session, row0 + 2)
        entry = _deal_entry(session, deal_list, ordinal)
        if entry == 0:
            raise RuntimeError("retail ranked deal entry is null")
        entry_raw = session.read_memory(entry, 0x10)
        source_slot = struct.unpack("<h", entry_raw[0:2])[0]
        target_slot = struct.unpack("<h", entry_raw[2:4])[0]
        score = struct.unpack("<i", entry_raw[8:12])[0]
        if stages is not None:
            stages.setdefault("deals", []).append(
                {
                    "index": index,
                    "dispatch": dispatch,
                    "ordinal": ordinal,
                    "source": source_slot,
                    "target": target_slot,
                    "score": score,
                    "list_size": _deal_list_size(session, deal_list),
                }
            )
        target_country = _eval_int(
            session,
            f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * target_slot:08x}",
        )
        transfer = _invoke_virtual(
            session,
            target_country,
            _VT_GET_AMT_UNSOLD,
            records,
            occurrences,
            breakpoint_roles,
            args=(dispatch,),
        )
        transfer = ((transfer & 0xFFFF) - 0x10000) if transfer & 0x8000 else transfer & 0xFFFF
        if target_slot < 7 <= source_slot:
            capacity = _invoke_virtual(
                session,
                target_country,
                _VT_GET_MERCHANT_CAPACITY,
                records,
                occurrences,
                breakpoint_roles,
            )
            capacity = ((capacity & 0xFFFF) - 0x10000) if capacity & 0x8000 else capacity & 0xFFFF
            if capacity < transfer:
                transfer = capacity
        if transfer > 0:
            buyer = _eval_int(
                session,
                f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * source_slot:08x}",
            )
            buyer_power = (
                _nation_pointer(session, source_slot) if source_slot < 7 else 0
            )
            still_buying = 0
            if (
                buyer_power != 0
                and _eval_int(
                    session, f"*(unsigned char*)0x{buyer_power + 0xA0:08x}"
                )
                != 0
            ):
                still_buying = _invoke_virtual(
                    session,
                    buyer,
                    _VT_STILL_BUYING_ITEM,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(dispatch,),
                )
            if buyer_power != 0 and still_buying & 0xFF != 0:
                _invoke_thiscall(
                    session,
                    _SET_DEAL_RESULTS,
                    trade_mgr,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(source_slot, target_slot, transfer, score, dispatch, 0, 0),
                )
            else:
                _invoke_virtual(
                    session,
                    buyer,
                    _VT_REPLY_TO_TRADE_OFFER,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(target_slot, transfer, score, dispatch),
                )
        ordinal += 1
        session.assign(f"*(short*)0x{row0 + 2:08x}", ordinal)
        if ordinal > _deal_list_size(session, deal_list):
            while True:
                index = _s16(session, row0) + 1
                session.assign(f"*(short*)0x{row0:08x}", index)
                if index > 0x10:
                    break
                dispatch = _s16(session, _TRADE_DEAL_CATEGORY_ORDER + 2 * index)
                deal_list = _eval_int(
                    session,
                    f"*(unsigned int*)0x{trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch:08x}",
                )
                if _deal_list_size(session, deal_list) != 0:
                    break
            session.assign(f"*(short*)0x{row0 + 2:08x}", 1)
            if stages is not None:
                stages[f"drain_to_{index}"] = _capture_trade_phase(session)[
                    "market_rows"
                ]

    if stages is not None:
        stages["drain_end"] = _capture_trade_phase(session)["market_rows"]

    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _CLEAR_TRADE_OFFERS,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )

    if stages is not None:
        stages["clear_done"] = _capture_trade_phase(session)["market_rows"]

    # Fold the turn-history offer cells: 0x11 rows x 0x17 cells, each cell raised
    # to the running maximum seen 23 cells earlier (deliberately reads across the
    # sub-row boundary into the next contiguous row). Indices are absolute shorts
    # from tradeOfferCells[0] of row 0, matching retail's rowCursor walk.
    cells_base = trade_mgr + _TRADE_ROW_BASE + 0x18
    fold_bytes = _TRADE_CATEGORY_COUNT * _TRADE_ROW_STRIDE - 0x18 + 2
    values = list(
        struct.unpack(
            f"<{fold_bytes // 2}h", session.read_memory(cells_base, fold_bytes)
        )
    )
    original = list(values)
    for row in range(0x11):
        for cell in range(0x17):
            current = row * 0x50 + 46 + cell
            if values[current - 0x17] > values[current]:
                values[current] = values[current - 0x17]
    # Assign only changed cells: bulk -data-write-memory-bytes payloads corrupt
    # memory under winedbg's gdb stub (observed zeroed market rows).
    for index in range(46, len(values)):
        if values[index] != original[index]:
            session.assign(
                f"*(short*)0x{cells_base + 2 * index:08x}", values[index]
            )
    if stages is not None:
        stages["fold_done"] = _capture_trade_phase(session)["market_rows"]


def _capture_trade_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    trade_mgr = _eval_int(session, f"*(unsigned int*)0x{_TRADE_MGR:08x}")
    diplomacy_mgr = _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")
    rows = []
    # The maximum-offer sub-row intentionally runs 23 cells past the declared
    # array boundary into the following row (or the trailing padding on row 16).
    rows_region = session.read_memory(
        trade_mgr + _TRADE_ROW_BASE, _TRADE_CATEGORY_COUNT * _TRADE_ROW_STRIDE + 2
    )
    for index in range(17):
        raw = rows_region[index * _TRADE_ROW_STRIDE : (index + 1) * _TRADE_ROW_STRIDE]
        cells = struct.unpack(
            "<69h",
            rows_region[
                index * _TRADE_ROW_STRIDE + 0x18 : index * _TRADE_ROW_STRIDE + 0x18 + 138
            ],
        )
        rows.append(
            {
                "previous_price": struct.unpack("<h", raw[4:6])[0],
                "price": struct.unpack("<h", raw[6:8])[0],
                "base_price": struct.unpack("<h", raw[0x16:0x18])[0],
                "request_count": struct.unpack("<h", raw[8:10])[0],
                "offer_count": struct.unpack("<h", raw[10:12])[0],
                "amount_offered": struct.unpack("<h", raw[0x14:0x16])[0],
                "adjusted_offer_count": struct.unpack("<d", raw[0x0C:0x14])[0],
                "current_offer_by_nation": list(cells[:23]),
                "maximum_offer_by_nation": list(cells[46:69]),
            }
        )
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        arrays = struct.unpack(
            "<115h", session.read_memory(nation + 0x1C6, 230)
        )
        city = _eval_int(session, f"*(unsigned int*)0x{nation + 0x894:08x}")
        city_stocks = (
            list(struct.unpack("<23h", session.read_memory(city + 0xB6, 46)))
            if city != 0
            else None
        )
        nations.append(
            {
                "treasury": _eval_int(session, f"*(int*)0x{nation + 0x10:08x}"),
                "available_merchant": _s16(session, nation + 0xA2),
                "merchant_capacity": _s16(session, nation + 0xA4),
                "transport_capacity": _s16(session, nation + 0xA6),
                "reserved_transport": _s16(session, nation + 0xA8),
                "unfilled_trade_offer_count": _s16(session, nation + 0xB0),
                "item_potentials": list(arrays[0:23]),
                "unfilled_trade_turns": list(arrays[23:46]),
                "transported_items": list(arrays[46:69]),
                "remembered_trade_offers": list(arrays[69:92]),
                "purchased_items": list(
                    struct.unpack("<23h", session.read_memory(nation + 0x198, 46))
                ),
                "city_stocks": city_stocks,
            }
        )
    last_processed = _eval_int(
        session, f"*(signed char*)0x{diplomacy_mgr + 0x78E:08x}"
    )
    if last_processed > 0x7F:
        last_processed -= 0x100
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "last_processed_nation": last_processed,
        "market_rows": rows,
        "trade_nations": nations,
    }


# --- city_transport_phase retail drive -------------------------------------------
# Mirrors NativeCityTransportCases.cpp RunCityAndTransportPhase: seed one
# non-capital owned region for development plus the active nation's
# pendingActionStatus.byAction[10], then invoke TSimMgr::DoCityAndTransport.

_GLOBAL_MAP_STATE = 0x006A43D4
_DO_CITY_AND_TRANSPORT = 0x0057F140
_PROVINCE_STRIDE = 0xA8
_TERRAIN_RECORD_STRIDE = 0x24


def _s8(session: GdbSession, address: int) -> int:
    value = _eval_int(session, f"*(signed char*)0x{address:08x}") & 0xFF
    return value - 0x100 if value & 0x80 else value


def _u32(session: GdbSession, address: int) -> int:
    return _eval_int(session, f"*(unsigned int*)0x{address:08x}")


def _longint_list_entries(session: GdbSession, list_pointer: int) -> list[int]:
    """Walk a retail TLongintList (CList<long,long> node chain)."""
    entries: list[int] = []
    if list_pointer == 0:
        return entries
    node = _u32(session, list_pointer + 4)
    while node != 0:
        entries.append(_eval_int(session, f"*(int*)0x{node + 8:08x}"))
        node = _u32(session, node)
    return entries


def _seed_city_transport(session: GdbSession) -> int:
    """Mirror SeedNonCapitalOwnedRegionDevelopment on the retail process.

    Returns the chosen region id, or raises when the fixture has no eligible
    non-capital province (the native case fails the same way).
    """
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    city_score_table = _u32(session, map_state + 0x10)
    terrain_table = _u32(session, map_state + 0x0C)
    active_slot = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, active_slot)
    if nation == 0 or map_state == 0:
        raise RuntimeError("retail loaded game has no active nation or map state")
    city = _u32(session, nation + 0x894)
    owned_regions = _u32(session, nation + 0x90)
    if city == 0 or owned_regions == 0:
        raise RuntimeError("retail active nation has no city or region list")

    economic_turn = _s16(session, sim_mgr + 0x2C)
    home_tile = _s16(session, nation + 0x88)
    chosen_id = -1
    for region_id in _longint_list_entries(session, owned_regions):
        province = city_score_table + region_id * _PROVINCE_STRIDE
        session.assign(f"*(short*)0x{province + 0x06:08x}", economic_turn)
        if (
            chosen_id == -1
            and _s16(session, province + 0x04) != home_tile
            and _s8(session, province + 0x3A) > 0
        ):
            chosen_id = region_id
    if chosen_id == -1:
        raise RuntimeError(
            "retail fixture has no non-capital owned province with linked tiles"
        )

    chosen = city_score_table + chosen_id * _PROVINCE_STRIDE
    session.assign(f"*(short*)0x{chosen + 0x06:08x}", economic_turn - 6)
    session.assign(f"*(signed char*)0x{chosen + 0x02:08x}", 0)
    for index in range(10):
        session.assign(f"*(short*)0x{chosen + 0x82 + 2 * index:08x}", 0)

    linked = _s16(session, chosen + 0x42)
    tile = terrain_table + linked * _TERRAIN_RECORD_STRIDE
    session.assign(f"*(signed char*)0x{tile + 0x11:08x}", 0)
    session.assign(f"*(signed char*)0x{tile + 0x12:08x}", -1)
    session.assign(f"*(signed char*)0x{tile + 0x0C:08x}", 3)

    session.assign(f"*(short*)0x{city + 0x1DC + 2:08x}", 4)
    session.assign(f"*(signed char*)0x{nation + 0x8C8 + 10:08x}", 0x32)
    return chosen_id


def _drive_city_transport_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    _seed_city_transport(session)
    sim_mgr = _u32(session, _SIM_MGR)
    # Match the srand(0x1234) in RunCityAndTransportPhase so minister tie-break
    # rand() draws line up between retail and recomp.
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    _invoke_thiscall(
        session,
        _DO_CITY_AND_TRANSPORT,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _capture_city_transport_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    city_score_table = _u32(session, map_state + 0x10)
    terrain_table = _u32(session, map_state + 0x0C)
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        arrays = struct.unpack(
            "<115h", session.read_memory(nation + 0x1C6, 230)
        )
        city = _u32(session, nation + 0x894)
        pending = [
            byte - 0x100 if byte & 0x80 else byte
            for byte in session.read_memory(nation + 0x8C8, 0x0D)
        ]
        entry: dict[str, object] = {
            "treasury": _eval_int(session, f"*(int*)0x{nation + 0x10:08x}"),
            "pending_actions": pending,
            "reserved_transport": _s16(session, nation + 0xA8),
            "item_potentials": list(arrays[0:23]),
            "transported_items": list(arrays[46:69]),
            "purchased_items": list(
                struct.unpack("<23h", session.read_memory(nation + 0x198, 46))
            ),
            "production_orders": None,
            "production_accum": None,
            "production_flags": None,
            "city_stocks": None,
        }
        if city != 0:
            entry["production_orders"] = list(
                struct.unpack("<16h", session.read_memory(city + 0x1DC, 32))
            )
            entry["production_accum"] = list(
                struct.unpack("<16h", session.read_memory(city + 0x1FC, 32))
            )
            entry["production_flags"] = list(session.read_memory(city + 0x21C, 16))
            entry["city_stocks"] = list(
                struct.unpack("<23h", session.read_memory(city + 0xB6, 46))
            )
        nations.append(entry)
    regions: list[dict[str, object]] = []
    active_slot = _s16(session, sim_mgr + 0x2E)
    active_nation = _nation_pointer(session, active_slot)
    if active_nation != 0:
        for region_id in _longint_list_entries(
            session, _u32(session, active_nation + 0x90)
        ):
            province = city_score_table + region_id * _PROVINCE_STRIDE
            raw = session.read_memory(province, _PROVINCE_STRIDE)
            linked = struct.unpack("<h", raw[0x42:0x44])[0]
            region: dict[str, object] = {
                "region_id": region_id,
                "development_stage": struct.unpack("<b", raw[0x02:0x03])[0],
                "last_turn_tick": struct.unpack("<h", raw[0x06:0x08])[0],
                "city_score": struct.unpack("<i", raw[0x9C:0xA0])[0],
                "dev_counts": list(
                    struct.unpack("<10h", raw[0x82 : 0x82 + 20])
                ),
                "linked_tile": linked,
                "linked_dev_class": None,
                "linked_edge0": None,
                "linked_edge1": None,
            }
            if linked >= 0:
                tile = session.read_memory(
                    terrain_table + linked * _TERRAIN_RECORD_STRIDE,
                    _TERRAIN_RECORD_STRIDE,
                )
                region["linked_dev_class"] = struct.unpack(
                    "<b", tile[0x0C:0x0D]
                )[0]
                region["linked_edge0"] = struct.unpack("<b", tile[0x11:0x12])[0]
                region["linked_edge1"] = struct.unpack("<b", tile[0x12:0x13])[0]
            regions.append(region)
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": active_slot,
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "city_transport": {"nations": nations, "regions": regions},
    }


# --- civilians_phase retail drive -------------------------------------------------
# Mirrors NativeDevelopmentCases.cpp RunCiviliansPhaseCase: the same tile-search
# helpers run against a snapshot of terrainStateTable, then TCivUnit objects are
# constructed via retail operator new + ICivUnit + SetOrders/MoveTo inferior
# calls, and TSimMgr::DoCivilians runs the phase.

_OPERATOR_NEW = 0x00606F73
_CIV_UNIT_CTOR = 0x005C28C0
_ICIV_UNIT = 0x005C2940
_CIV_SET_ORDERS = 0x005C29F0
_CIV_MOVE_TO = 0x005C2B70
_APPLY_RAIL_FLAGS = 0x00513FF0
_DO_CIVILIANS = 0x0057F200
_CIV_UNIT_SIZE = 0x28
_TILE_COUNT = 0x1950
_PROVINCE_COUNT = 0x180
# g_Build_Hex_Area_LookupTable_00696E70/_00696E80: per-direction scaled-column /
# row deltas consumed by TMapMgr::GetNeighborTileID (0x512cc0).
_HEX_COL_DELTAS = 0x00696E70
_HEX_ROW_DELTAS = 0x00696E80
_HEX_DIRECTION_COUNT = 6
_HEX_DIRECTION_EAST = 1
_TERRAIN_WATER = 5


class _TerrainSnapshot:
    """Byte-level view of terrainStateTable + cityScoreTable for the Find* scans."""

    def __init__(self, session: GdbSession, map_state: int) -> None:
        self.session = session
        self.map_state = map_state
        self.terrain_base = _u32(session, map_state + 0x0C)
        self.province_base = _u32(session, map_state + 0x10)
        self.tiles = b""
        self.provinces = b""

    def refresh_tiles(self) -> None:
        chunks = []
        total = _TILE_COUNT * _TERRAIN_RECORD_STRIDE
        for offset in range(0, total, 0x2000):
            chunks.append(
                self.session.read_memory(
                    self.terrain_base + offset, min(0x2000, total - offset)
                )
            )
        self.tiles = b"".join(chunks)

    def refresh_provinces(self) -> None:
        total = _PROVINCE_COUNT * _PROVINCE_STRIDE
        chunks = []
        for offset in range(0, total, 0x2000):
            chunks.append(
                self.session.read_memory(
                    self.province_base + offset, min(0x2000, total - offset)
                )
            )
        self.provinces = b"".join(chunks)

    def tile_field(self, tile: int, offset: int, fmt: str) -> int:
        base = tile * _TERRAIN_RECORD_STRIDE + offset
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.tiles[base : base + size])[0]

    def has_civilian(self, tile: int) -> bool:
        base = tile * _TERRAIN_RECORD_STRIDE + 0x20
        return struct.unpack("<I", self.tiles[base : base + 4])[0] != 0

    def province_city_tile(self, province: int) -> int:
        base = province * _PROVINCE_STRIDE + 0x04
        return struct.unpack("<h", self.provinces[base : base + 2])[0]


def _neighbor_tile(
    tile: int, direction: int, col_deltas: list[int], row_deltas: list[int]
) -> int:
    """Mirror TMapMgr::GetNeighborTileID (0x512cc0)."""
    row, col = divmod(tile, 0x6C)
    scaled = (row % 2) + col * 2 + col_deltas[direction]
    wrapped_row = row + row_deltas[direction]
    if scaled > 0xD7:
        scaled -= 0xD9
    elif scaled < 0:
        scaled += 0xD8
    wrapped_row = min(max(wrapped_row, 0), 0x3B)
    result = (scaled >> 1) + wrapped_row * 0x6C
    return result if 0 <= result < _TILE_COUNT else -1


def _find_unoccupied_rail_section(
    snapshot: _TerrainSnapshot, col_deltas: list[int], row_deltas: list[int]
) -> tuple[int, int]:
    for candidate in range(_TILE_COUNT):
        if (
            snapshot.has_civilian(candidate)
            or snapshot.tile_field(candidate, 0x06, "<b") != 0
            or snapshot.tile_field(candidate, 0x17, "<B") != 0
        ):
            continue
        neighbor = _neighbor_tile(
            candidate, _HEX_DIRECTION_EAST, col_deltas, row_deltas
        )
        if neighbor == -1 or neighbor == candidate:
            continue
        if (
            not snapshot.has_civilian(neighbor)
            and snapshot.tile_field(neighbor, 0x06, "<b") == 0
            and snapshot.tile_field(neighbor, 0x17, "<B") == 0
        ):
            return candidate, neighbor
    return -1, -1


def _find_unoccupied_tile(snapshot: _TerrainSnapshot) -> int:
    for candidate in range(_TILE_COUNT):
        if not snapshot.has_civilian(candidate):
            return candidate
    return -1


def _find_unoccupied_province_tile(snapshot: _TerrainSnapshot) -> int:
    for candidate in range(_TILE_COUNT):
        if snapshot.has_civilian(candidate):
            continue
        province = snapshot.tile_field(candidate, 0x14, "<h")
        if province < 0 or province >= _PROVINCE_COUNT:
            continue
        if snapshot.province_city_tile(province) < 0:
            continue
        return candidate
    return -1


def _find_owned_construction_tile(
    snapshot: _TerrainSnapshot,
    nation_slot: int,
    required_flags: int,
    forbidden_flags: int,
) -> int:
    for candidate in range(_TILE_COUNT):
        if snapshot.has_civilian(candidate):
            continue
        if snapshot.tile_field(candidate, 0x04, "<b") != nation_slot:
            continue
        flags = snapshot.tile_field(candidate, 0x1C, "<H")
        if (flags & required_flags) != required_flags or (
            flags & forbidden_flags
        ) != 0:
            continue
        return candidate
    return -1


def _find_owned_coastal_construction_tile(
    snapshot: _TerrainSnapshot,
    nation_slot: int,
    forbidden_flags: int,
    col_deltas: list[int],
    row_deltas: list[int],
) -> int:
    for candidate in range(_TILE_COUNT):
        if snapshot.has_civilian(candidate):
            continue
        if snapshot.tile_field(candidate, 0x04, "<b") != nation_slot:
            continue
        if (
            snapshot.tile_field(candidate, 0x1C, "<H") & forbidden_flags
        ) != 0:
            continue
        for direction in range(_HEX_DIRECTION_COUNT):
            neighbor = _neighbor_tile(
                candidate, direction, col_deltas, row_deltas
            )
            if neighbor == -1:
                continue
            if (
                snapshot.tile_field(neighbor, 0x00, "<b")
                == _TERRAIN_WATER
            ):
                return candidate
    return -1


def _new_civilian_unit(
    session: GdbSession,
    kind: int,
    tile: int,
    nation_slot: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    unit = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_CIV_UNIT_SIZE,),
    )
    _invoke_thiscall(
        session, _CIV_UNIT_CTOR, unit, records, occurrences, breakpoint_roles
    )
    _invoke_thiscall(
        session,
        _ICIV_UNIT,
        unit,
        records,
        occurrences,
        breakpoint_roles,
        args=(kind, tile, nation_slot),
    )
    return unit


def _set_orders(
    session: GdbSession,
    unit: int,
    order: int,
    payload: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    remaining_turns: "int | None" = None,
) -> None:
    _invoke_thiscall(
        session,
        _CIV_SET_ORDERS,
        unit,
        records,
        occurrences,
        breakpoint_roles,
        args=(order, payload),
    )
    if remaining_turns is not None:
        session.assign(f"*(short*)0x{unit + 0x24:08x}", remaining_turns)


def _town_marker_count(session: GdbSession, nation: int) -> int:
    town_list = _u32(session, nation + 0x898)
    if town_list == 0:
        return -1
    # TSortedList embeds CPtrList at +0x04; m_nCount sits at +0x10.
    return _eval_int(session, f"*(int*)0x{town_list + 0x10:08x}")


def _drive_civilians_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    economic_turn: int | None = None,
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    if economic_turn is not None:
        session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", economic_turn)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    active_slot = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, active_slot)
    if nation == 0 or map_state == 0:
        raise RuntimeError("retail loaded game has no civilian state")

    col_deltas = list(
        struct.unpack(
            "<6h",
            session.read_memory(_HEX_COL_DELTAS, 2 * _HEX_DIRECTION_COUNT),
        )
    )
    row_deltas = list(
        struct.unpack(
            "<6h",
            session.read_memory(_HEX_ROW_DELTAS, 2 * _HEX_DIRECTION_COUNT),
        )
    )
    snapshot = _TerrainSnapshot(session, map_state)
    snapshot.refresh_tiles()
    snapshot.refresh_provinces()

    source_tile, destination_tile = _find_unoccupied_rail_section(
        snapshot, col_deltas, row_deltas
    )
    if source_tile < 0:
        raise RuntimeError("retail map has no clear rail section")
    engineer = _new_civilian_unit(
        session, 4, source_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _APPLY_RAIL_FLAGS,
        map_state,
        records,
        occurrences,
        breakpoint_roles,
        args=(source_tile, destination_tile, active_slot),
    )
    _set_orders(
        session, engineer, 5, source_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    _invoke_thiscall(
        session,
        _CIV_MOVE_TO,
        engineer,
        records,
        occurrences,
        breakpoint_roles,
        args=(destination_tile,),
    )
    snapshot.refresh_tiles()

    prospect_tile = _find_unoccupied_tile(snapshot)
    if prospect_tile < 0:
        raise RuntimeError("retail map has no unoccupied prospecting tile")
    prospector = _new_civilian_unit(
        session, 1, prospect_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, prospector, 8, prospect_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    snapshot.refresh_tiles()

    develop_tile = _find_unoccupied_tile(snapshot)
    if develop_tile < 0:
        raise RuntimeError("retail map has no unoccupied development tile")
    miner = _new_civilian_unit(
        session, 0, develop_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, miner, 10, develop_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    snapshot.refresh_tiles()

    fort_tile = _find_unoccupied_province_tile(snapshot)
    if fort_tile < 0:
        raise RuntimeError("retail map has no unoccupied province tile")
    fort_engineer = _new_civilian_unit(
        session, 4, fort_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, fort_engineer, 12, fort_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    snapshot.refresh_tiles()

    purchase_tile = _find_unoccupied_tile(snapshot)
    if purchase_tile < 0:
        raise RuntimeError("retail map has no unoccupied purchase tile")
    developer = _new_civilian_unit(
        session, 7, purchase_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, developer, 13, purchase_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    snapshot.refresh_tiles()

    sleep_tile = _find_unoccupied_tile(snapshot)
    if sleep_tile < 0:
        raise RuntimeError("retail map has no unoccupied sleep tile")
    sleeper = _new_civilian_unit(
        session, 2, sleep_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, sleeper, 2, sleep_tile, records, occurrences,
        breakpoint_roles,
    )
    snapshot.refresh_tiles()

    redeploy_tile = _find_unoccupied_tile(snapshot)
    if redeploy_tile < 0:
        raise RuntimeError("retail map has no unoccupied redeploy tile")
    traveler = _new_civilian_unit(
        session, 5, redeploy_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, traveler, 1, redeploy_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    snapshot.refresh_tiles()

    depot_tile = _find_owned_construction_tile(snapshot, active_slot, 0, 0x24)
    if depot_tile < 0:
        raise RuntimeError(
            "retail map has no owned depot construction tile"
        )
    depot_engineer = _new_civilian_unit(
        session, 4, depot_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, depot_engineer, 6, depot_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )
    snapshot.refresh_tiles()

    port_tile = _find_owned_coastal_construction_tile(
        snapshot, active_slot, 0x30, col_deltas, row_deltas
    )
    if port_tile < 0:
        raise RuntimeError(
            "retail map has no owned coastal port construction tile"
        )
    port_flags = snapshot.tile_field(port_tile, 0x1C, "<H") | 1
    session.assign(
        f"*(unsigned short*)0x{snapshot.terrain_base + port_tile * _TERRAIN_RECORD_STRIDE + 0x1C:08x}",
        port_flags,
    )
    port_engineer = _new_civilian_unit(
        session, 4, port_tile, active_slot, records, occurrences,
        breakpoint_roles,
    )
    _set_orders(
        session, port_engineer, 7, port_tile, records, occurrences,
        breakpoint_roles, remaining_turns=1,
    )

    town_counts_before = [
        _town_marker_count(session, _nation_pointer(session, slot))
        for slot in range(_MAJOR_NATION_COUNT)
    ]

    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    _invoke_thiscall(
        session,
        _DO_CIVILIANS,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )

    # Mirror the native post-pass: zero hasAdjacentCity (TTown+0x4e) only on
    # towns this phase created (ordinals beyond townCountsBefore).
    for slot in range(_MAJOR_NATION_COUNT):
        nation_ptr = _nation_pointer(session, slot)
        town_list = _u32(session, nation_ptr + 0x898) if nation_ptr else 0
        before = town_counts_before[slot]
        if town_list == 0 or before < 0:
            continue
        node = _u32(session, town_list + 0x08)
        ordinal = 1
        while node != 0:
            if ordinal > before:
                town = _u32(session, node + 8)
                session.assign(
                    f"*(unsigned char*)0x{town + 0x4E:08x}", 0
                )
            node = _u32(session, node)
            ordinal += 1


def _capture_civilians_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    terrain_base = _u32(session, map_state + 0x0C)
    units: list[dict[str, object]] = []
    total = _TILE_COUNT * _TERRAIN_RECORD_STRIDE
    tiles = b""
    chunks = []
    for offset in range(0, total, 0x2000):
        chunks.append(
            session.read_memory(terrain_base + offset, min(0x2000, total - offset))
        )
    tiles = b"".join(chunks)
    for tile_index in range(_TILE_COUNT):
        base = tile_index * _TERRAIN_RECORD_STRIDE
        head = struct.unpack("<I", tiles[base + 0x20 : base + 0x24])[0]
        unit = head
        while unit != 0:
            raw = session.read_memory(unit, _CIV_UNIT_SIZE)
            units.append(
                {
                    "tile": tile_index,
                    "kind": struct.unpack("<h", raw[0x04:0x06])[0],
                    "order": struct.unpack("<h", raw[0x08:0x0A])[0],
                    "target": struct.unpack("<h", raw[0x0C:0x0E])[0],
                    "owner": struct.unpack("<h", raw[0x18:0x1A])[0],
                    "remaining_turns": struct.unpack("<h", raw[0x24:0x26])[0],
                    "completion_marker": struct.unpack("<h", raw[0x26:0x28])[0],
                }
            )
            unit = struct.unpack("<I", raw[0x14:0x18])[0]
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        city = _u32(session, nation + 0x894)
        nations.append(
            {
                "treasury": _eval_int(
                    session, f"*(int*)0x{nation + 0x10:08x}"
                ),
                "town_count": _town_marker_count(session, nation),
                "city_stocks": (
                    list(
                        struct.unpack(
                            "<23h", session.read_memory(city + 0xB6, 46)
                        )
                    )
                    if city != 0
                    else None
                ),
            }
        )
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "civilians": {"units": units, "nations": nations},
    }


# --- military_phase retail drive --------------------------------------------------
# Mirrors NativeMilitaryCases.cpp RunMilitaryPhase: economicTurn = 6, pinned
# srand, then TSimMgr::DoMilitary (0x57f280).

_DO_MILITARY = 0x0057F280
_DO_COMBAT_MOVES = 0x004A1E40
_TUNIT_SET_ORDERS = 0x005C2630
_TTACTICAL_BATTLE_NEXT_MOVE = 0x005A0E20
_MAP_ACTION_CONTEXT_MANAGER = 0x006A3338
_NAVY_PRIMARY_ORDER_LIST_HEAD = 0x006A3EDC
_NAVY_ORDER_MANAGER = 0x006A43E4
_MAP_ACTION_CONTEXT_LIST_HEAD = 0x006A3FC8
_TSHIP_CTOR = 0x0054F500
_TSHIP_ISHIP = 0x0054F7B0
_TTASKFORCE_SUBMIT_ORDERS = 0x005540B0
_ZONE_CREATE_TASK_FORCE = 0x005609E0
_TSHIP_SIZE = 0x38
_FIND_FIRST_PORT_ZONE = 0x00563540
_OCEAN_SINGLETON = 0x006A3FBC
_ADVANCE_TURN_STATE = 0x0057DA70
_TECH_MGR = 0x006A43D8
_RELATION_WAR = 6
_RELATION_PROPAGATION_MATRIX = 0xBBE
_UNIT_ORDER_IDLE = 0
_UNIT_ORDER_REDEPLOY = 1
_TACTICAL_BATTLE_IN_PROGRESS = 0
_FINISH_TACTICAL_ACTION = 0x005A0D60
_TARMY_PLAYER_ADVANCE_PULSE = 0x0059E3E0
_TARMY_PLAYER_CURSOR_PROFILE = 0x0059C440


def _drive_military_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    economic_turn: int = 6,
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", economic_turn)
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    _invoke_thiscall(
        session,
        _DO_MILITARY,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _sorted_ptr_list_entries(session: GdbSession, list_pointer: int) -> list[int]:
    """Walk a TSortedList's embedded CPtrList node chain (listState at +0x04)."""
    entries: list[int] = []
    if list_pointer == 0:
        return entries
    node = _u32(session, list_pointer + 0x08)
    while node != 0:
        entries.append(_u32(session, node + 8))
        node = _u32(session, node)
    return entries


def _capture_military_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        units: list[dict[str, object]] = []
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, nation + 0x44)
        ):
            raw = session.read_memory(unit, 0x40)
            units.append(
                {
                    "kind": struct.unpack("<h", raw[0x04:0x06])[0],
                    "tile": struct.unpack("<h", raw[0x06:0x08])[0],
                    "order": struct.unpack("<h", raw[0x08:0x0A])[0],
                    "target": struct.unpack("<h", raw[0x0C:0x0E])[0],
                    "owner": struct.unpack("<h", raw[0x18:0x1A])[0],
                    "strength": struct.unpack("<h", raw[0x34:0x36])[0],
                    "experience": struct.unpack("<h", raw[0x38:0x3A])[0],
                    "battle_flags": struct.unpack("<h", raw[0x3A:0x3C])[0],
                }
            )
        nations.append(
            {
                "treasury": _eval_int(
                    session, f"*(int*)0x{nation + 0x10:08x}"
                ),
                "military_expenses": _eval_int(
                    session, f"*(int*)0x{nation + 0x960:08x}"
                ),
                "units": units,
            }
        )
    ships: list[dict[str, object]] = []
    ship = _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD)
    while ship != 0:
        raw = session.read_memory(ship, 0x38)
        location = struct.unpack("<I", raw[0x08:0x0C])[0]
        zone_ordinal = -1
        if location != 0:
            zone_ordinal = _s16(session, location + 0x14)
        ships.append(
            {
                "type": struct.unpack("<h", raw[0x04:0x06])[0],
                "nation": struct.unpack("<h", raw[0x14:0x16])[0],
                "strength": struct.unpack("<h", raw[0x1C:0x1E])[0],
                "experience": struct.unpack("<h", raw[0x30:0x32])[0],
                "zone": zone_ordinal,
            }
        )
        ship = struct.unpack("<I", raw[0x24:0x28])[0]
    task_forces: list[dict[str, object]] = []
    navy_mgr = _u32(session, _NAVY_ORDER_MANAGER)
    force = _u32(session, navy_mgr + 0x04) if navy_mgr != 0 else 0
    while force != 0:
        raw = session.read_memory(force, 0x34)
        location = struct.unpack("<I", raw[0x18:0x1C])[0]
        zone_ordinal = -1
        if location != 0:
            zone_ordinal = _s16(session, location + 0x14)
        children = 0
        child = struct.unpack("<I", raw[0x10:0x14])[0]
        while child != 0:
            children += 1
            child = _u32(session, child + 0x04)
        task_forces.append(
            {
                "nation": struct.unpack("<h", raw[0x1C:0x1E])[0],
                "aggression": struct.unpack("<i", raw[0x04:0x08])[0],
                "ship_orders": struct.unpack("<i", raw[0x08:0x0C])[0],
                "zone": zone_ordinal,
                "defeated": raw[0x26],
                "child_count": children,
            }
        )
        force = struct.unpack("<I", raw[0x2C:0x30])[0]
    province_owners: list[int] = []
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    if map_state != 0:
        province_base = _u32(session, map_state + 0x10)
        provinces = b""
        total = _PROVINCE_COUNT * _PROVINCE_STRIDE
        for offset in range(0, total, 0x2000):
            provinces += session.read_memory(
                province_base + offset, min(0x2000, total - offset)
            )
        province_owners = [
            struct.unpack(
                "<b",
                provinces[
                    index * _PROVINCE_STRIDE : index * _PROVINCE_STRIDE + 1
                ],
            )[0]
            for index in range(_PROVINCE_COUNT)
        ]
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    battle = _u32(session, army_mgr + 0x3A4) if army_mgr != 0 else 0
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "military": {
            "nations": nations,
            "ships": ships,
            "task_forces": task_forces,
            "province_owners": province_owners,
            "land_battle": {
                "created": battle != 0,
                "outcome": _s16(session, battle + 0x44) if battle != 0 else -1,
            },
        },
    }


# --- second_turn_military_cleanup retail drive --------------------------------
# Mirrors RunSecondTurnMilitaryCleanup / the case-0x15 epilogue of
# AdvanceGlobalTurnStateMachine: ClearAllTransientOrders, then for non-client
# sessions the heatmap + priority-metric recompute and per-nation AI replan,
# then AddPurchasedItems for each terrain-eligible major nation.

_RECOMPUTE_HEATMAP = 0x00518130
_RECOMPUTE_PRIORITY_METRICS = 0x0053FE30
_CLEAR_TRANSIENT_ORDERS = 0x00557040
# Vtable byte offsets verified in the retail case-0x15 epilogue
# (0x57e0d7 call [edx+0x2b8], 0x57e122 call [edx+0x108]); slot 0 is MFC
# CObject::GetRuntimeClass, and classTAutoGreatPower is the retail
# CRuntimeClass global for TAutoGreatPower.
_VT_GET_RUNTIME_CLASS = 0x00
_VT_REFRESH_AND_REPLAN = 0x2B8
_VT_ADD_PURCHASED_ITEMS = 0x108
_CLASS_AUTO_GREAT_POWER = 0x00653F90
_CLEANUP_METRIC_GLOBALS = {
    "queue_divergence": 0x006A3A88,
    "mobile_score": 0x006A3B88,
    "mobile_divergence": 0x006A3AE0,
    "combined_divergence": 0x006A3B50,
    "weighted_military": 0x006A3B20,
}
_PROVINCE_CITY_SCORE = 0x9C


def _runtime_class(
    session: GdbSession,
    receiver: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    """Call MFC CObject::GetRuntimeClass (vtable slot 0) on receiver."""
    return _invoke_virtual(
        session,
        receiver,
        _VT_GET_RUNTIME_CLASS,
        records,
        occurrences,
        breakpoint_roles,
    )


def _nation_terrain_eligible(session: GdbSession, slot: int) -> int:
    """Mirror IsNationTerrainEligible for slots 0..6 (terrain + nation non-null,
    encodedNationSlot outside the 100..199 minor band). Returns the nation
    pointer or 0."""
    nation = _nation_pointer(session, slot)
    country = _u32(session, _TERRAIN_TABLE + 4 * slot)
    if nation == 0 or country == 0:
        return 0
    code = _s16(session, country + 0x0E)
    if 100 <= code <= 199:
        return 0
    return nation


def _drive_second_turn_military_cleanup(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 2)
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    navy_mgr = _u32(session, _NAVY_ORDER_MANAGER)
    if navy_mgr != 0:
        _invoke_thiscall(
            session,
            _CLEAR_TRANSIENT_ORDERS,
            navy_mgr,
            records,
            occurrences,
            breakpoint_roles,
        )
    if _eval_int(session, f"*(int*)0x{sim_mgr + 0x44:08x}") != 2:
        map_state = _u32(session, _GLOBAL_MAP_STATE)
        if map_state != 0:
            _invoke_thiscall(
                session,
                _RECOMPUTE_HEATMAP,
                map_state,
                records,
                occurrences,
                breakpoint_roles,
            )
        _invoke_thiscall(
            session,
            _RECOMPUTE_PRIORITY_METRICS,
            0,
            records,
            occurrences,
            breakpoint_roles,
        )
        for slot in range(_MAJOR_NATION_COUNT):
            nation = _nation_terrain_eligible(session, slot)
            if nation == 0:
                continue
            _invoke_virtual(
                session,
                nation,
                _VT_REFRESH_AND_REPLAN,
                records,
                occurrences,
                breakpoint_roles,
                args=(0,),
            )
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_terrain_eligible(session, slot)
        if nation == 0:
            continue
        _invoke_virtual(
            session,
            nation,
            _VT_ADD_PURCHASED_ITEMS,
            records,
            occurrences,
            breakpoint_roles,
        )


def _capture_military_cleanup(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    region_scores: list[int] = []
    city_score_total = 0
    if map_state != 0:
        city_score_total = _eval_int(
            session, f"*(int*)0x{map_state + 0x18:08x}"
        )
        table = _u32(session, map_state + 0x10)
        if table != 0:
            raw = b""
            total = _PROVINCE_COUNT * _PROVINCE_STRIDE
            for offset in range(0, total, 0x2000):
                raw += session.read_memory(
                    table + offset, min(0x2000, total - offset)
                )
            region_scores = [
                struct.unpack(
                    "<i",
                    raw[
                        index * _PROVINCE_STRIDE
                        + _PROVINCE_CITY_SCORE : index * _PROVINCE_STRIDE
                        + _PROVINCE_CITY_SCORE
                        + 4
                    ],
                )[0]
                for index in range(_PROVINCE_COUNT)
            ]
    cleanup: dict[str, object] = {
        "region_scores": region_scores,
        "city_score_total": city_score_total,
    }
    cleanup.update(
        _capture_priority_metrics(session, records, occurrences, breakpoint_roles)
    )
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "military_cleanup": cleanup,
    }


# --- recompute_nation_order_priority_metrics retail drive ---------------------
# Mirrors RunRecomputeNationOrderPriorityMetrics: the metric function alone,
# with its result payload (IEEE-754 bits) mirrored from the retail globals.


def _capture_priority_metrics(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    metrics: dict[str, object] = {}
    for key, address in _CLEANUP_METRIC_GLOBALS.items():
        raw = session.read_memory(address, 7 * 4)
        metrics[key] = [
            struct.unpack("<I", raw[index * 4 : index * 4 + 4])[0]
            for index in range(7)
        ]
    for key, offset in (
        ("expansion_pressure", 0xB64),
        ("unit_divergence", 0xB68),
        ("mission_pressure", 0xB6C),
    ):
        values: list[int] = []
        for slot in range(_MAJOR_NATION_COUNT):
            nation = _nation_pointer(session, slot)
            if nation != 0 and _runtime_class(
                session, nation, records, occurrences, breakpoint_roles
            ) == _CLASS_AUTO_GREAT_POWER:
                values.append(_u32(session, nation + offset))
            else:
                values.append(0)
        metrics[key] = values
    return metrics


def _drive_recompute_metrics(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    _invoke_thiscall(
        session,
        _RECOMPUTE_PRIORITY_METRICS,
        0,
        records,
        occurrences,
        breakpoint_roles,
    )


def _write_name_string(
    session: GdbSession,
    name: str,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    """Allocate a scratch buffer in the inferior and fill it byte-by-byte.

    Bulk -data-write-memory-bytes payloads silently corrupt under the winedbg
    stub (see the trade-phase fold note), so small strings go through per-byte
    assigns instead.
    """
    encoded = name.encode("ascii") + b"\x00"
    buffer = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(len(encoded),),
    )
    for index, byte in enumerate(encoded):
        session.assign(f"*(char*)0x{buffer + index:08x}", byte)
    return buffer


def _new_ship(
    session: GdbSession,
    ship_type: int,
    zone: int,
    nation_slot: int,
    name: str,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    ship = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_TSHIP_SIZE,),
    )
    _invoke_thiscall(
        session, _TSHIP_CTOR, ship, records, occurrences, breakpoint_roles
    )
    name_pointer = _write_name_string(
        session, name, records, occurrences, breakpoint_roles
    )
    _invoke_thiscall(
        session,
        _TSHIP_ISHIP,
        ship,
        records,
        occurrences,
        breakpoint_roles,
        args=(ship_type, zone, nation_slot, name_pointer),
    )
    return ship


def _find_unoccupied_zone(session: GdbSession) -> int:
    """Mirror FindUnoccupiedMapZone: first zone no primary-order ship occupies."""
    occupied: set[int] = set()
    ship = _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD)
    while ship != 0:
        occupied.add(_u32(session, ship + 0x08))
        ship = _u32(session, ship + 0x24)
    zone = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
    while zone != 0:
        if zone not in occupied:
            return zone
        zone = _u32(session, zone + 0x18)
    return 0


def _force_war_between(session: GdbSession, left: int, right: int) -> None:
    diplomacy_mgr = _u32(session, _DIPLOMACY_MGR)
    matrix = diplomacy_mgr + _RELATION_PROPAGATION_MATRIX
    session.assign(
        f"*(short*)0x{matrix + 2 * (left * _NATION_SLOT_COUNT + right):08x}",
        _RELATION_WAR,
    )
    session.assign(
        f"*(short*)0x{matrix + 2 * (right * _NATION_SLOT_COUNT + left):08x}",
        _RELATION_WAR,
    )


def _drive_military_phase_naval_encounter(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    attacker_type: int = 3,
    defender_type: int = 3,
) -> dict[str, object]:
    """Mirror RunMilitaryPhaseNavalEncounter: two hostile task forces sharing
    one zone, a forced war relation, then TSimMgr::DoMilitary."""
    sim_mgr = _u32(session, _SIM_MGR)
    active_nation = _s16(session, sim_mgr + 0x2E)
    hostile_nation = -1
    for slot in range(_MAJOR_NATION_COUNT):
        if slot != active_nation and _nation_pointer(session, slot) != 0:
            hostile_nation = slot
            break
    zone = _find_unoccupied_zone(session)
    if hostile_nation < 0 or zone == 0:
        raise RuntimeError("the fixture cannot create a naval encounter")
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    _new_ship(
        session,
        attacker_type,
        zone,
        active_nation,
        "military-encounter-attacker",
        records,
        occurrences,
        breakpoint_roles,
    )
    attacker = _invoke_thiscall(
        session,
        _ZONE_CREATE_TASK_FORCE,
        zone,
        records,
        occurrences,
        breakpoint_roles,
        args=(active_nation,),
    )
    if attacker == 0:
        raise RuntimeError("could not create the attacking task force")
    _invoke_thiscall(
        session,
        _TTASKFORCE_SUBMIT_ORDERS,
        attacker,
        records,
        occurrences,
        breakpoint_roles,
        args=(3, 0),
    )
    _new_ship(
        session,
        defender_type,
        zone,
        hostile_nation,
        "military-encounter-defender",
        records,
        occurrences,
        breakpoint_roles,
    )
    defender = _invoke_thiscall(
        session,
        _ZONE_CREATE_TASK_FORCE,
        zone,
        records,
        occurrences,
        breakpoint_roles,
        args=(hostile_nation,),
    )
    if defender == 0:
        raise RuntimeError("could not create the defending task force")
    _invoke_thiscall(
        session,
        _TTASKFORCE_SUBMIT_ORDERS,
        defender,
        records,
        occurrences,
        breakpoint_roles,
        args=(6, zone),
    )
    _force_war_between(session, active_nation, hostile_nation)
    diplomacy_mgr = _u32(session, _DIPLOMACY_MGR)
    gate = {
        "at_war": _invoke_thiscall(
            session,
            0x004EF540,
            diplomacy_mgr,
            records,
            occurrences,
            breakpoint_roles,
            args=(hostile_nation, active_nation),
        )
        & 0xFF,
        "stale": _invoke_thiscall(
            session,
            0x004EF590,
            diplomacy_mgr,
            records,
            occurrences,
            breakpoint_roles,
            args=(hostile_nation, active_nation),
        )
        & 0xFF,
    }
    pre = {
        "setup": {
            "active_nation": active_nation,
            "hostile_nation": hostile_nation,
            "zone": zone,
            "attacker": attacker,
            "defender": defender,
            "gate": gate,
            "military": _capture_military_phase(session)["military"],
        }
    }
    _invoke_thiscall(
        session,
        _DO_MILITARY,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    return pre


def _drive_military_phase_ships_without_orders(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    """Mirror RunMilitaryPhaseShipsWithoutOrders: economicTurn=6, pinned srand,
    two unordered active-nation ships (a damaged type 3 and a ready type 9) in
    the nation's first port zone, then TSimMgr::DoMilitary (0x57f280)."""
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 6)
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    active_nation = _s16(session, sim_mgr + 0x2E)
    zone = _invoke_thiscall(
        session,
        _FIND_FIRST_PORT_ZONE,
        _u32(session, _OCEAN_SINGLETON),
        records,
        occurrences,
        breakpoint_roles,
        args=(active_nation,),
    )
    if zone == 0:
        raise RuntimeError("the fixture has no active-nation port zone")
    damaged = _new_ship(
        session,
        3,
        zone,
        active_nation,
        "military-unordered-damaged",
        records,
        occurrences,
        breakpoint_roles,
    )
    session.assign(f"*(short*)0x{damaged + 0x1C:08x}", 1)
    _new_ship(
        session,
        9,
        zone,
        active_nation,
        "military-unordered-ready",
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _DO_MILITARY,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _drive_second_turn_sequence(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunSecondTurnSequence: economicTurn=2, turnStateCode=5,
    preferenceValues[8]=0, tech unlock flags and priority slots cleared, then
    AdvanceGlobalTurnStateMachine (0x57da70) pumped until the deal book
    (0x0e), newspaper (0x12), and player-orders (5) stops are reached."""
    sim_mgr = _u32(session, _SIM_MGR)
    tech_mgr = _u32(session, _TECH_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 2)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 5)
    session.assign(f"*(short*)0x{sim_mgr + 0x58:08x}", 0)
    for tech in range(3, 0x1D):
        session.assign(f"*(char*)0x{tech_mgr + 0x180 + tech:08x}", 0)
        session.assign(f"*(short*)0x{tech_mgr + 0x04 + 2 * tech:08x}", 0)
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    stops: list[int] = []
    targets = iter((0x0E, 0x12, 0x05))
    wanted = next(targets, None)
    step = 0
    while wanted is not None:
        if step >= 96:
            raise RuntimeError(
                f"retail turn sequence stalled before state {wanted:#x}"
            )
        step += 1
        _invoke_thiscall(
            session,
            _ADVANCE_TURN_STATE,
            sim_mgr,
            records,
            occurrences,
            breakpoint_roles,
        )
        state = _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}")
        if state == wanted:
            stops.append(state)
            wanted = next(targets, None)
    return {
        "stops": stops,
        "economic_turn": _s16(session, sim_mgr + 0x2C),
    }


def _drive_second_turn_diplomacy_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    """Mirror RunSecondTurnDiplomacyPhase: economicTurn=2, pinned srand,
    ApplyDiplomacyInterNationStatesForTurn (0x4f01e0), then each major's
    ReplyToDiplomacyOffers (0x4df5f0)."""
    sim_mgr = _u32(session, _SIM_MGR)
    diplomacy_mgr = _u32(session, _DIPLOMACY_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 2)
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    _invoke_thiscall(
        session,
        _APPLY_DIPLOMACY_TURN,
        diplomacy_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _REPLY_TO_OFFERS,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )


def _resolved_tile_owner(session: GdbSession, owner_code: int) -> int:
    """Mirror TMapMgr::ResolveTileOwnerNationCodeNormalized (0x514120)."""
    if owner_code < 0:
        return owner_code
    nation = _u32(session, _TERRAIN_TABLE + 4 * owner_code)
    if nation == 0:
        return owner_code
    encoded = _s16(session, nation + 0x0E)
    if encoded < 200:
        return owner_code
    return encoded - 200


def _find_hostile_redeploy(
    session: GdbSession, snapshot: _TerrainSnapshot
) -> tuple[int, int, int]:
    """Mirror FindHostileRedeploy: first unit with an adjacent enemy-garrisoned
    province. Returns (unit, destination region, defender nation slot)."""
    for slot in range(_NATION_SLOT_COUNT):
        country = _u32(session, _TERRAIN_TABLE + slot * 4)
        if country == 0:
            continue
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, country + 0x44)
        ):
            source = _s16(session, unit + 0x06)
            if source < 0 or source >= _PROVINCE_COUNT:
                continue
            record = snapshot.provinces[
                source * _PROVINCE_STRIDE : (source + 1) * _PROVINCE_STRIDE
            ]
            owner = struct.unpack("<b", record[0x00:0x01])[0]
            adjacent_count = struct.unpack("<b", record[0x08:0x09])[0]
            for adj in range(adjacent_count):
                dest = struct.unpack(
                    "<h", record[0x0A + 2 * adj : 0x0C + 2 * adj]
                )[0]
                if dest < 0 or dest >= _PROVINCE_COUNT:
                    continue
                destination = snapshot.provinces[
                    dest * _PROVINCE_STRIDE : (dest + 1) * _PROVINCE_STRIDE
                ]
                if (
                    struct.unpack("<b", destination[0x00:0x01])[0] == owner
                    or struct.unpack("<I", destination[0x98:0x9C])[0] == 0
                ):
                    continue
                defender = _resolved_tile_owner(
                    session, struct.unpack("<b", destination[0x00:0x01])[0]
                )
                if defender < 0:
                    continue
                return unit, dest, defender
    return 0, -1, -1


def _next_tactical_move(
    session: GdbSession,
    battle: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    _invoke_thiscall(
        session,
        _TTACTICAL_BATTLE_NEXT_MOVE,
        battle,
        records,
        occurrences,
        breakpoint_roles,
    )


def _pump_battle_to_active_input(
    session: GdbSession,
    battle: int,
    active_nation: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> bool:
    """Mirror PumpArmyBattleToActiveNationInput: step NextMove until either the
    battle decides or the current side is the unwatched active nation waiting
    on end-of-action input."""
    player14 = _u32(session, battle + 0x14)
    player18 = _u32(session, battle + 0x18)
    guard = 20000
    while _s16(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS:
        side = _eval_int(session, f"*(int*)0x{battle + 0x0C:08x}")
        player = player14 if side == 0 else player18
        if (
            _eval_int(session, f"*(char*)0x{battle + 0x48:08x}") & 0xFF != 0
            and _eval_int(session, f"*(int*)0x{player + 0x1C:08x}")
            == active_nation
            and _eval_int(session, f"*(char*)0x{player + 0x0E:08x}") & 0xFF
            == 0
        ):
            return True
        if guard <= 0:
            return False
        guard -= 1
        _next_tactical_move(
            session, battle, records, occurrences, breakpoint_roles
        )
    return True


def _drive_military_phase_land_combat(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    mode: str = "auto",
) -> None:
    """Mirror RunMilitaryPhaseLandCombat: pinned srand, clear all military
    orders, issue one hostile redeploy under a forced war, then run the real
    TArmyMgr::DoCombatMoves (0x4a1e40) and pump the tactical battle via
    TTacticalBattle::NextMove (0x5a0e20) until the outcome is decided.

    With interactive=True the attacker is made the active nation and the
    battle is pumped to the active nation's input, "Done" is posted via
    FinishTacticalActionAndPostNextMoveCommand (0x5a0d60), then the rest
    auto-resolves -- mirroring RunMilitaryPhaseLandInteractive."""
    sim_mgr = _u32(session, _SIM_MGR)
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    for slot in range(_NATION_SLOT_COUNT):
        country = _u32(session, _TERRAIN_TABLE + slot * 4)
        if country == 0:
            continue
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, country + 0x44)
        ):
            _invoke_thiscall(
                session,
                _TUNIT_SET_ORDERS,
                unit,
                records,
                occurrences,
                breakpoint_roles,
                args=(_UNIT_ORDER_IDLE, -1),
            )
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    snapshot = _TerrainSnapshot(session, map_state)
    snapshot.refresh_provinces()
    unit, dest, defender = _find_hostile_redeploy(session, snapshot)
    if unit == 0:
        raise RuntimeError(
            "the loaded fixture has no adjacent enemy-garrisoned province"
        )
    owner = _s16(session, unit + 0x18)
    _force_war_between(session, owner, defender)
    _invoke_thiscall(
        session,
        _TUNIT_SET_ORDERS,
        unit,
        records,
        occurrences,
        breakpoint_roles,
        args=(_UNIT_ORDER_REDEPLOY, dest),
    )
    if mode != "auto":
        # g_pSimMgr->activeNationSlot = attacker owner.
        session.assign(f"*(short*)0x{sim_mgr + 0x2E:08x}", owner)
    # preferenceValues[0] = 0 -> unattended battles auto-resolve.
    session.assign(f"*(short*)0x{sim_mgr + 0x48:08x}", 0)
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    _invoke_thiscall(
        session,
        _DO_COMBAT_MOVES,
        army_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    battle = _u32(session, army_mgr + 0x3A4)
    if mode == "auto":
        guard = 20000
        while (
            battle != 0
            and _s16(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS
        ):
            if guard <= 0:
                raise RuntimeError("retail tactical auto did not terminate")
            guard -= 1
            _next_tactical_move(
                session, battle, records, occurrences, breakpoint_roles
            )
        return
    if battle == 0:
        raise RuntimeError("hostile orders did not create a land battle")
    active_nation = _s16(session, sim_mgr + 0x2E)
    player14 = _u32(session, battle + 0x14)
    player18 = _u32(session, battle + 0x18)
    # StopActiveNationArmyPlayerForInput: watch only the active nation's side.
    for player in (player14, player18):
        watched = (
            _eval_int(session, f"*(int*)0x{player + 0x1C:08x}")
            == active_nation
        )
        session.assign(
            f"*(char*)0x{player + 0x0E:08x}", 0 if watched else 1
        )
    if not _pump_battle_to_active_input(
        session, battle, active_nation, records, occurrences, breakpoint_roles
    ):
        raise RuntimeError("retail battle did not reach active-nation input")
    if mode == "retreat":
        # Mirror RunInteractiveArmyBattleRetreat: order the current side to
        # retreat (fieldF=1, stance profile 0) and pulse the tactical turn.
        side = _eval_int(session, f"*(int*)0x{battle + 0x0C:08x}")
        current = player14 if side == 0 else player18
        session.assign(f"*(char*)0x{current + 0x0F:08x}", 1)
        session.assign(f"*(char*)0x{current + 0x0E:08x}", 1)
        _invoke_thiscall(
            session,
            _TARMY_PLAYER_CURSOR_PROFILE,
            current,
            records,
            occurrences,
            breakpoint_roles,
            args=(0,),
        )
        _invoke_thiscall(
            session,
            _TARMY_PLAYER_ADVANCE_PULSE,
            current,
            records,
            occurrences,
            breakpoint_roles,
        )
    else:
        _invoke_thiscall(
            session,
            _FINISH_TACTICAL_ACTION,
            battle,
            records,
            occurrences,
            breakpoint_roles,
        )
        if not _pump_battle_to_active_input(
            session,
            battle,
            active_nation,
            records,
            occurrences,
            breakpoint_roles,
        ):
            raise RuntimeError(
                "retail Done did not reach the next active-nation input"
            )
    # AutoArmyBattleToCommit: unwatched both sides, pulse a pending end of
    # action, then run NextMove to a decision plus one extra step.
    session.assign(f"*(char*)0x{player14 + 0x0E:08x}", 1)
    session.assign(f"*(char*)0x{player18 + 0x0E:08x}", 1)
    if _eval_int(session, f"*(char*)0x{battle + 0x48:08x}") & 0xFF != 0:
        side = _eval_int(session, f"*(int*)0x{battle + 0x0C:08x}")
        current = player14 if side == 0 else player18
        _invoke_thiscall(
            session,
            _TARMY_PLAYER_ADVANCE_PULSE,
            current,
            records,
            occurrences,
            breakpoint_roles,
        )
    guard = 20000
    while _s16(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS:
        if guard <= 0:
            raise RuntimeError("retail tactical auto did not terminate")
        guard -= 1
        _next_tactical_move(
            session, battle, records, occurrences, breakpoint_roles
        )
    _next_tactical_move(
        session, battle, records, occurrences, breakpoint_roles
    )


def _read_diplomacy_records(session: GdbSession, queue: int) -> list[dict[str, int]]:
    if queue == 0:
        return []
    size = _eval_int(session, f"*(int*)0x{queue + 8:08x}")
    data = _eval_int(session, f"*(unsigned int*)0x{queue + 4:08x}")
    if size <= 0 or data == 0:
        return []
    entries = struct.unpack(f"<{size}I", session.read_memory(data, 4 * size))
    records: list[dict[str, int]] = []
    for entry in entries:
        code, source = struct.unpack("<2h", session.read_memory(entry, 4))
        records.append({"code": code, "source": source})
    return records


def _capture_diplomacy_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    diplomacy_mgr = _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        block = session.read_memory(nation + 0xB2, 4 * _NATION_SLOT_COUNT)
        policies = list(struct.unpack(f"<{_NATION_SLOT_COUNT}h", block[: 2 * _NATION_SLOT_COUNT]))
        grants = list(struct.unpack(f"<{_NATION_SLOT_COUNT}h", block[2 * _NATION_SLOT_COUNT :]))
        nations.append(
            {
                "treasury": _eval_int(session, f"*(int*)0x{nation + 0x10:08x}"),
                "policies": policies,
                "grants": grants,
                "proposals": _read_diplomacy_records(
                    session,
                    _eval_int(session, f"*(unsigned int*)0x{nation + 0x84C:08x}"),
                ),
                "turn_events": _read_diplomacy_records(
                    session,
                    _eval_int(session, f"*(unsigned int*)0x{nation + 0x848:08x}"),
                ),
            }
        )
    last_processed = _eval_int(
        session, f"*(signed char*)0x{diplomacy_mgr + 0x78E:08x}"
    )
    if last_processed > 0x7F:
        last_processed -= 0x100
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _eval_int(session, f"*(short*)0x{sim_mgr + 0x2E:08x}"),
        "economic_turn": _eval_int(session, f"*(short*)0x{sim_mgr + 0x2C:08x}"),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "last_processed_nation": last_processed,
        "diplomacy_nations": nations,
    }


def run_binary(
    scenario: Scenario,
    kind: str,
    executable: Path,
    addresses: dict[str, int],
    control_addresses: dict[str, int],
    run_dir: Path,
    timeout_seconds: float,
) -> Trace:
    artifact_dir = run_dir / kind
    artifact_dir.mkdir(parents=True, exist_ok=True)
    prefix = artifact_dir / "prefix"
    environment = prefix_environment(prefix)
    display_context = virtual_display(environment, artifact_dir / "xvfb.log")
    display = display_context.__enter__()
    try:
        initialize_wine_prefix(prefix, environment)
        game_dir, staged_fixture, asset_manifest_sha256 = prepare_game_sandbox(
            artifact_dir, executable, scenario.fixture
        )
    except BaseException:
        display_context.__exit__(None, None, None)
        raise
    if staged_fixture is None:
        raise RuntimeError("differential retail fixture was not staged")
    sandbox_executable = game_dir / "Imperialism.exe"
    fixture_argument = windows_path(staged_fixture, environment)
    session = GdbSession(
        sandbox_executable,
        game_dir,
        environment,
        artifact_dir,
        arguments=(fixture_argument,),
    )
    records: list[dict] = []
    metadata = {
        "scenario": scenario.name,
        "binary_kind": kind,
        "binary": file_identity(executable),
        "sandbox_binary": file_identity(sandbox_executable),
        "fixture": file_identity(scenario.fixture),
        "retail_asset_manifest_sha256": asset_manifest_sha256,
        "display": display,
        "source_assets_read_only": True,
        "status": "running",
    }
    occurrences: dict[str, int] = {}
    shell_command_address = direct_call_target_after(
        executable,
        control_addresses["initialization_owner"],
        control_addresses["before_shell_callee"],
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        session.start(auto_continue=False)
        breakpoint_roles: dict[str, tuple[str, Probe | None]] = {}
        deferred_number = session.set_breakpoint(shell_command_address)
        breakpoint_roles[deferred_number] = ("defer_shell_command", None)
        replay_number: str | None = None
        replay_address: int | None = None
        terminal_return_number: str | None = None
        for probe in scenario.probes:
            number = session.set_breakpoint(addresses[probe.probe_id])
            breakpoint_roles[number] = ("probe", probe)
        deferred_context: tuple[int, int, int, int] | None = None
        session.continue_inferior()
        while time.monotonic() < deadline:
            stop = session.wait_for_stop(min(1.0, deadline - time.monotonic()))
            if stop is None:
                if session.process.poll() is not None:
                    raise RuntimeError(
                        f"{kind} exited with {session.process.returncode} before the stop checkpoint"
                    )
                continue
            if is_terminal_stop(stop):
                raise RuntimeError(f"{kind} exited before the stop checkpoint")
            if stop.reason != "breakpoint-hit":
                session.capture_stop(f"unexpected-{stop.signal_name or stop.reason}", stop)
                raise RuntimeError(
                    f"{kind} stopped unexpectedly: {stop.signal_name or stop.reason}"
                )
            role = breakpoint_roles.get(stop.breakpoint_number or "")
            if role is None:
                raise RuntimeError(
                    f"{kind} hit unknown breakpoint {stop.breakpoint_number}"
                )
            role_name, probe = role
            if role_name == "defer_shell_command":
                if deferred_context is not None:
                    raise RuntimeError(f"{kind} entered the deferred shell command twice")
                app = int(session.evaluate("$ecx"), 0)
                command_info = int(session.evaluate("*(unsigned int*)($esp+4)"), 0)
                shell_command = int(
                    session.evaluate(f"*(int*)0x{command_info + 0x10:08x}"), 0
                )
                if shell_command != 1:
                    raise RuntimeError(
                        f"{kind} expected CCommandLineInfo::FileOpen (1), got {shell_command}"
                    )
                filename = int(
                    session.evaluate(f"*(unsigned int*)0x{command_info + 0x14:08x}"), 0
                )
                deferred_context = (app, command_info, shell_command, filename)
                session.assign(f"*(int*)0x{command_info + 0x10:08x}", 0)
                session.continue_inferior()
                continue
            if role_name == "replay_shell_command":
                if deferred_context is None:
                    raise RuntimeError(f"{kind} reached replay before shell-command deferral")
                if replay_number is None or replay_address is None:
                    raise RuntimeError(f"{kind} reached an unconfigured shell-command replay")
                app, command_info, shell_command, filename = deferred_context
                session.delete_breakpoint(deferred_number)
                session.delete_breakpoint(replay_number)
                session.assign(
                    f"*(int*)0x{command_info + 0x10:08x}", shell_command
                )
                vtable = int(session.evaluate(f"*(unsigned int*)0x{app:08x}"), 0)
                open_document = int(
                    session.evaluate(f"*(unsigned int*)0x{vtable + 0x84:08x}"), 0
                )
                stack = int(session.evaluate("$esp"), 0)
                session.assign(f"*(unsigned int*)0x{stack - 4:08x}", filename)
                session.assign(f"*(unsigned int*)0x{stack - 8:08x}", replay_address)
                session.assign("$esp", stack - 8)
                session.assign("$ecx", app)
                session.assign("$eip", open_document)
                session.continue_inferior()
                continue
            if role_name == "terminal_checkpoint":
                fields = _capture_fields(
                    session,
                    Probe(
                        scenario.terminal_checkpoint.checkpoint_id,
                        0,
                        scenario.terminal_checkpoint.fields,
                    ),
                )
                records.append(
                    {
                        "type": "checkpoint",
                        "seq": len(records),
                        "probe": scenario.terminal_checkpoint.checkpoint_id,
                        "occurrence": 1,
                        "fields": fields,
                    }
                )
                if scenario.drive:
                    if terminal_return_number is not None:
                        session.delete_breakpoint(terminal_return_number)
                    if scenario.drive == "diplomacy_phase":
                        _drive_diplomacy_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_diplomacy_phase(session)
                        result_probe = CHECKPOINT_DIPLOMACY_PHASE
                    elif scenario.drive == "second_turn_diplomacy_phase":
                        _drive_second_turn_diplomacy_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_diplomacy_phase(session)
                        result_probe = CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE
                    elif scenario.drive == "trade_phase":
                        stages: dict[str, object] = {}
                        result_fields = {
                            "pre": _capture_trade_phase(session),
                            "stages": stages,
                        }
                        _drive_trade_phase(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            stages,
                        )
                        result_fields.update(_capture_trade_phase(session))
                        result_probe = CHECKPOINT_TRADE_PHASE
                    elif scenario.drive == "second_turn_trade_phase":
                        second_stages: dict[str, object] = {}
                        result_fields = {
                            "pre": _capture_trade_phase(session),
                            "stages": second_stages,
                        }
                        _drive_trade_phase(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            second_stages,
                            economic_turn=2,
                        )
                        result_fields.update(_capture_trade_phase(session))
                        result_probe = CHECKPOINT_SECOND_TURN_TRADE_PHASE
                    elif scenario.drive == "city_transport_phase":
                        _drive_city_transport_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_city_transport_phase(session)
                        result_probe = CHECKPOINT_CITY_TRANSPORT_PHASE
                    elif scenario.drive == "civilians_phase":
                        _drive_civilians_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_civilians_phase(session)
                        result_probe = CHECKPOINT_CIVILIANS_PHASE
                    elif scenario.drive == "second_turn_civilians_phase":
                        _drive_civilians_phase(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            economic_turn=2,
                        )
                        result_fields = _capture_civilians_phase(session)
                        result_probe = CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE
                    elif scenario.drive == "military_phase":
                        _drive_military_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_military_phase(session)
                        result_probe = CHECKPOINT_MILITARY_PHASE
                    elif scenario.drive == "second_turn_military_phase":
                        _drive_military_phase(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            economic_turn=2,
                        )
                        result_fields = _capture_military_phase(session)
                        result_probe = CHECKPOINT_SECOND_TURN_MILITARY_PHASE
                    elif scenario.drive == "second_turn_military_cleanup":
                        _drive_second_turn_military_cleanup(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_military_cleanup(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP
                    elif scenario.drive == "recompute_nation_order_priority_metrics":
                        _drive_recompute_metrics(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_priority_metrics(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_RECOMPUTE_METRICS
                    elif scenario.drive in (
                        "military_phase_naval_encounter",
                        "military_phase_naval_escalation",
                    ):
                        result_fields = _drive_military_phase_naval_encounter(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            *( (9, 3)
                               if scenario.drive
                               == "military_phase_naval_escalation"
                               else () ),
                        )
                        result_fields.update(_capture_military_phase(session))
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in (
                        "military_phase_land_combat",
                        "military_phase_land_interactive",
                        "military_phase_land_retreat",
                    ):
                        _drive_military_phase_land_combat(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            mode={
                                "military_phase_land_combat": "auto",
                                "military_phase_land_interactive": "interactive",
                                "military_phase_land_retreat": "retreat",
                            }[scenario.drive],
                        )
                        result_fields = _capture_military_phase(session)
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "second_turn_sequence":
                        result_fields = _drive_second_turn_sequence(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_SECOND_TURN_SEQUENCE
                    elif (
                        scenario.drive
                        == "military_phase_ships_without_orders"
                    ):
                        _drive_military_phase_ships_without_orders(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_military_phase(session)
                        result_probe = CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE
                    else:
                        raise RuntimeError(
                            f"unknown scenario drive {scenario.drive!r}"
                        )
                    records.append(
                        {
                            "type": "checkpoint",
                            "seq": len(records),
                            "probe": result_probe,
                            "occurrence": 1,
                            "fields": result_fields,
                        }
                    )
                metadata["status"] = "completed"
                break
            if probe is None:
                raise RuntimeError(f"{kind} probe breakpoint has no probe definition")
            occurrence = occurrences.get(probe.probe_id, 0) + 1
            occurrences[probe.probe_id] = occurrence
            fields = _capture_fields(session, probe)
            record = {
                "type": "checkpoint",
                "seq": len(records),
                "probe": probe.probe_id,
                "occurrence": occurrence,
                "fields": fields,
            }
            records.append(record)
            if (
                probe.probe_id == scenario.start_action.rewrite_probe
                and fields.get(scenario.start_action.rewrite_field)
                == scenario.start_action.rewrite_from
            ):
                session.assign(
                    scenario.start_action.rewrite_expression,
                    scenario.start_action.rewrite_to,
                )
                record["action_id"] = scenario.start_action.rewrite_action_id
                record["effective_event"] = scenario.start_action.rewrite_to
            if (
                deferred_context is not None
                and replay_number is None
                and probe.probe_id == scenario.start_action.replay_after.probe
                and fields.get(scenario.start_action.replay_after.field)
                == scenario.start_action.replay_after.equals
            ):
                replay_address = int(
                    session.evaluate("*(unsigned int*)$esp"), 0
                )
                replay_number = session.set_breakpoint(replay_address)
                breakpoint_roles[replay_number] = ("replay_shell_command", None)
            if (
                probe.probe_id == scenario.terminal_checkpoint.probe
                and fields.get(scenario.terminal_checkpoint.field)
                == scenario.terminal_checkpoint.equals
            ):
                if terminal_return_number is not None:
                    raise RuntimeError(f"{kind} reached terminal event twice")
                terminal_return_address = int(
                    session.evaluate("*(unsigned int*)$esp"), 0
                )
                terminal_return_number = session.set_breakpoint(terminal_return_address)
                breakpoint_roles[terminal_return_number] = ("terminal_checkpoint", None)
            session.continue_inferior()
        else:
            session.interrupt_and_capture("differential-timeout")
            raise RuntimeError(f"{kind} timed out before the stop checkpoint")
    except Exception as error:
        metadata["status"] = "partial"
        metadata["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if metadata["status"] == "running":
            metadata["status"] = "partial"
        _write_trace(artifact_dir / "trace.ndjson", metadata, records)
        session.close()
        shut_down_wine_prefix(environment)
        display_context.__exit__(None, None, None)
        shutil.rmtree(prefix, ignore_errors=True)
    return Trace(metadata, records)


def run_scenario(scenario: Scenario, timeout: float | None = None) -> int:
    timeout_seconds = scenario.timeout_seconds if timeout is None else timeout
    original_executable = Path(os.environ.get("ORIGINAL_BINARY", "")).resolve()
    if not original_executable.is_file():
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    control_original = {
        "initialization_owner": scenario.start_action.owner_address,
        "before_shell_callee": scenario.start_action.after_call_to,
    }
    run_id = f"{scenario.name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = RESULT_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    original_trace = run_binary(
        scenario,
        "retail",
        original_executable,
        {probe.probe_id: probe.original_address for probe in scenario.probes},
        control_original,
        run_dir,
        timeout_seconds,
    )
    if scenario.drive in {
        "diplomacy_phase",
        "trade_phase",
        "city_transport_phase",
        "civilians_phase",
        "military_phase",
        "military_phase_naval_encounter",
        "military_phase_naval_escalation",
        "military_phase_land_combat",
        "military_phase_land_interactive",
        "military_phase_land_retreat",
        "military_phase_ships_without_orders",
        "second_turn_military_phase",
        "second_turn_sequence",
        "second_turn_diplomacy_phase",
        "second_turn_trade_phase",
        "second_turn_civilians_phase",
        "second_turn_military_cleanup",
        "recompute_nation_order_priority_metrics",
    }:
        from tools.runtime.native_oracle import run_native_transition

        native_dir = run_dir / "recomp"
        native_dir.mkdir(parents=True, exist_ok=True)
        if (
            run_native_transition(
                scenario.native_test,
                timeout_seconds=timeout_seconds,
                result_dir=native_dir,
                fixture_dir=scenario.fixture.parent,
            )
            != 0
        ):
            raise RuntimeError(
                f"native transition {scenario.native_test} failed; see {native_dir}"
            )
        native_result = json.loads(
            (native_dir / "result.json").read_text(encoding="utf-8")
        )
        captures_path = native_dir / "captures.json"
        if captures_path.is_file():
            native_result["captures"] = json.loads(
                captures_path.read_text(encoding="utf-8")
            )
        if scenario.drive == "diplomacy_phase":
            recomp_observation = normalize_native_diplomacy_phase(native_result)
        elif scenario.drive == "second_turn_diplomacy_phase":
            recomp_observation = normalize_native_diplomacy_phase(
                native_result,
                checkpoint_id=CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE,
            )
        elif scenario.drive == "second_turn_trade_phase":
            recomp_observation = normalize_native_trade_phase(
                native_result,
                checkpoint_id=CHECKPOINT_SECOND_TURN_TRADE_PHASE,
            )
        elif scenario.drive == "second_turn_civilians_phase":
            recomp_observation = normalize_native_civilians_phase(
                native_result,
                checkpoint_id=CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE,
            )
        elif scenario.drive == "city_transport_phase":
            recomp_observation = normalize_native_city_transport_phase(
                native_result
            )
        elif scenario.drive == "civilians_phase":
            recomp_observation = normalize_native_civilians_phase(native_result)
        elif scenario.drive == "military_phase":
            recomp_observation = normalize_native_military_phase(native_result)
        elif scenario.drive in ("military_phase_naval_encounter",
                                "military_phase_naval_escalation"):
            recomp_observation = normalize_native_military_phase(native_result)
        elif scenario.drive == "military_phase_land_combat":
            recomp_observation = normalize_native_military_phase(
                native_result, checkpoint_id=CHECKPOINT_LAND_COMBAT_PHASE
            )
        elif scenario.drive == "military_phase_land_interactive":
            recomp_observation = normalize_native_military_phase(
                native_result, checkpoint_id=CHECKPOINT_LAND_INTERACTIVE_PHASE
            )
        elif scenario.drive == "military_phase_land_retreat":
            recomp_observation = normalize_native_military_phase(
                native_result, checkpoint_id=CHECKPOINT_LAND_RETREAT_PHASE
            )
        elif scenario.drive == "military_phase_ships_without_orders":
            recomp_observation = normalize_native_military_phase(
                native_result,
                checkpoint_id=CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
            )
        elif scenario.drive == "second_turn_military_phase":
            recomp_observation = normalize_native_military_phase(
                native_result,
                checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_PHASE,
            )
        elif scenario.drive == "recompute_nation_order_priority_metrics":
            recomp_observation = normalize_native_recompute_metrics(
                native_result
            )
        elif scenario.drive == "second_turn_military_cleanup":
            recomp_observation = normalize_native_military_cleanup(
                native_result,
                checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
            )
        elif scenario.drive == "second_turn_sequence":
            recomp_observation = normalize_native_second_turn_sequence(
                native_result
            )
        else:
            recomp_observation = normalize_native_trade_phase(native_result)
        recomp_identity = native_result.get("host", {}).get("provenance", {})
    else:
        native_outcome = RuntimeRunner(
            run_dir / "recomp", scenario.fixture.parent
        ).run(
            RunRequest(
                name=scenario.native_test,
                seed=1,
                timeout_seconds=timeout_seconds,
                rerun_seh=False,
                gdb_first=False,
                no_gdb=True,
                require_fixtures=True,
            )
        )
        if native_outcome.exit_code != 0:
            raise RuntimeError(
                f"native recomp driver {scenario.native_test} failed; see "
                f"{run_dir / 'recomp' / (scenario.native_test + '.json')}"
            )
        recomp_observation = normalize_native_combined_map(native_outcome.result)
        recomp_identity = native_outcome.result.get("host", {}).get("provenance", {})
    result_checkpoint = scenario.result_checkpoint_id or scenario.terminal_checkpoint.checkpoint_id
    retail_records = [
        record
        for record in original_trace.records
        if record.get("probe") == result_checkpoint
    ]
    if len(retail_records) != 1:
        raise RuntimeError(
            f"retail produced {len(retail_records)} result checkpoint records"
        )
    if result_checkpoint == CHECKPOINT_DIPLOMACY_PHASE:
        retail_observation = normalize_retail_diplomacy_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE:
        retail_observation = normalize_retail_diplomacy_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_TRADE_PHASE:
        retail_observation = normalize_retail_trade_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_SECOND_TURN_TRADE_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE:
        retail_observation = normalize_retail_civilians_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_TRADE_PHASE:
        retail_observation = normalize_retail_trade_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_CITY_TRANSPORT_PHASE:
        retail_observation = normalize_retail_city_transport_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_CIVILIANS_PHASE:
        retail_observation = normalize_retail_civilians_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_MILITARY_PHASE:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (CHECKPOINT_NAVAL_ENCOUNTER_PHASE,
                               CHECKPOINT_NAVAL_ESCALATION_PHASE):
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_LAND_COMBAT_PHASE:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_LAND_COMBAT_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_LAND_INTERACTIVE_PHASE:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_LAND_INTERACTIVE_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_LAND_RETREAT_PHASE:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_LAND_RETREAT_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_MILITARY_PHASE:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_PHASE,
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP:
        retail_observation = normalize_retail_military_cleanup(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
        )
    elif result_checkpoint == CHECKPOINT_RECOMPUTE_METRICS:
        retail_observation = normalize_retail_recompute_metrics(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_SEQUENCE:
        retail_observation = normalize_retail_second_turn_sequence(
            retail_records[0]["fields"]
        )
    else:
        retail_observation = normalize_retail_combined_map(retail_records[0]["fields"])
    validate_checkpoint(retail_observation)
    validate_checkpoint(recomp_observation)
    divergence = first_checkpoint_difference(retail_observation, recomp_observation)
    result = {
        "scenario": scenario.name,
        "evidence_kind": "retail_differential",
        "status": "matched" if divergence is None else "diverged",
        "execution": {
            "retail": "gdb_checkpoint_tape",
            "recomp": "native_runtime_driver",
        },
        "checkpoint_sequence": [result_checkpoint],
        "observations": {
            "retail": retail_observation,
            "recomp": recomp_observation,
        },
        "first_divergence": divergence,
        "binary_identities": {
            "retail": original_trace.metadata["binary"],
            "recomp": recomp_identity.get("runtime_executable"),
        },
        "fixture_identity": original_trace.metadata["fixture"],
        "retail_assets": {
            "source_read_only": original_trace.metadata["source_assets_read_only"],
            "manifest_sha256": original_trace.metadata["retail_asset_manifest_sha256"],
        },
        "excluded_noise": [
            "elapsed_ms",
            "idle_ticks",
            "process_ids",
            "debugger_stop_counts",
            "window_handles",
            "raw_pointer_values",
        ],
        "run_dir": str(run_dir),
    }
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (run_dir / "result.json").write_text(serialized, encoding="utf-8")
    (RESULT_DIR / f"{scenario.name}.json").write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if divergence is None else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("--timeout", type=float)
    args = parser.parse_args()
    try:
        return run_scenario(load_scenario(args.scenario), args.timeout)
    except (DebuggerTransportError, RuntimeError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    raise SystemExit(main())
