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
    CHECKPOINT_NAVAL_TIER_EXHAUSTION_PHASE,
    CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX,
    CHECKPOINT_LAND_COMBAT_PHASE,
    CHECKPOINT_LAND_INTERACTIVE_PHASE,
    CHECKPOINT_LAND_RETREAT_PHASE,
    CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
    CHECKPOINT_AI_NAVAL_DEVELOPMENT,
    CHECKPOINT_CHECK_TECH_ADVANCES,
    CHECKPOINT_CHECK_TECH_ADVANCES_AI,
    CHECKPOINT_TECH_NAVAL_UPGRADE,
    CHECKPOINT_TECH_NAVAL_SEQUENCE,
    CHECKPOINT_BATTLE_MELEE,
    CHECKPOINT_BATTLE_RANGED,
    CHECKPOINT_COMBAT_BATTLE,
    CHECKPOINT_COMBAT_RESUME,
    CHECKPOINT_COMBAT_THEN_MOVES,
    CHECKPOINT_COMBAT_UNCONTESTED,
    CHECKPOINT_NAVY_BATTLE_DEFENDER,
    CHECKPOINT_NAVY_BATTLE_DEPLOY,
    CHECKPOINT_ELIMINATION_PHASE,
    CHECKPOINT_PRESSURE_AI_NOOP,
    CHECKPOINT_PRESSURE_HUMAN_DEBT,
    CHECKPOINT_SEASON_ADVANCE,
    CHECKPOINT_TURN_ALERTS_FIRST,
    CHECKPOINT_TURN_ALERTS_LATER,
    CHECKPOINT_TURN_STOP_CITY_TRANSPORT,
    CHECKPOINT_TURN_STOP_DEAL_BOOK,
    CHECKPOINT_TURN_STOP_TECHNOLOGY,
    CHECKPOINT_TURN_STOP_TRADE,
    CHECKPOINT_TURN_STATE_AI_REPLAN,
    CHECKPOINT_TURN_STATE_AI_REASSESS_DAMAGED,
    CHECKPOINT_TURN_STATE_COMBAT_MOVES,
    CHECKPOINT_TURN_STATE_MILITARY_CLEANUP,
    ACTION_TURN_STATE_AI_REPLAN,
    ACTION_TURN_STATE_AI_REASSESS_DAMAGED,
    ACTION_TURN_STATE_COMBAT_MOVES,
    ACTION_TURN_STATE_MILITARY_CLEANUP,
    _PLAYER_DIPLOMACY_POLICY_SCENARIOS,
    _NATION_ECONOMY_SCENARIOS,
    _DIPLOMACY_ECONOMY_SCENARIOS,
    _PROVINCE_SCENARIOS,
    _DEVELOPMENT_SCENARIOS,
    _YIELD_SCENARIOS,
    _GROWTH_SCENARIOS,
    _TACTICAL_SNAPSHOT_SCENARIOS,
    _ARMY_MILITARY_SCENARIOS,
    _CITY_ITEM_ORDER_SCENARIOS,
    _OPENING_SCENARIOS,
    _PENDING_STATUS_SCENARIOS,
    _NEWS_SCENARIOS,
    _ARMY_UI_SCENARIOS,
    _NAVY_UI_SCENARIOS,
    CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
    CHECKPOINT_REASSESS_MISSIONS,
    CHECKPOINT_REASSESS_MISSIONS_DAMAGED,
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
    normalize_native_ai_naval_development,
    normalize_native_check_technology_advances,
    normalize_native_consecutive_turn_sequence,
    normalize_native_battle_attack,
    normalize_native_combat_moves,
    normalize_native_navy_battle_deploy,
    normalize_native_elimination_phase,
    normalize_native_great_power_pressure,
    normalize_native_season_advance,
    normalize_native_turn_alerts_first,
    normalize_native_turn_alerts_later,
    normalize_native_turn_stop_state,
    normalize_native_turn_stop_trade,
    normalize_native_turn_state_military_cleanup,
    normalize_native_player_diplomacy_policy,
    normalize_native_nation_economy,
    normalize_native_province_loss,
    normalize_native_province_ocean,
    normalize_native_development,
    normalize_native_yield_rebuild,
    normalize_native_specialist_recruitment,
    normalize_native_growth,
    normalize_native_advisory,
    normalize_native_battle_snapshots,
    normalize_native_city_item_order,
    normalize_native_opening,
    normalize_native_pending_status,
    normalize_native_news,
    normalize_native_army_ui,
    normalize_native_navy_ui,
    normalize_native_reassess_missions,
    normalize_native_recompute_metrics,
    normalize_native_rng_contract,
    normalize_native_military_phase,
    normalize_native_military_phase_naval_tier_exhaustion,
    normalize_native_strategic_naval_battle_matrix,
    normalize_native_second_turn_sequence,
    normalize_native_combined_map,
    normalize_native_diplomacy_phase,
    normalize_native_trade_phase,
    normalize_retail_city_transport_phase,
    normalize_retail_civilians_phase,
    normalize_retail_combined_map,
    normalize_retail_military_cleanup,
    normalize_retail_ai_naval_development,
    normalize_retail_check_technology_advances,
    normalize_retail_consecutive_turn_sequence,
    normalize_retail_battle_attack,
    normalize_retail_combat_moves,
    normalize_retail_navy_battle_deploy,
    normalize_retail_elimination_phase,
    normalize_retail_great_power_pressure,
    normalize_retail_season_advance,
    normalize_retail_turn_alerts_first,
    normalize_retail_turn_alerts_later,
    normalize_retail_turn_stop_state,
    normalize_retail_turn_stop_trade,
    normalize_retail_turn_state_military_cleanup,
    normalize_retail_player_diplomacy_policy,
    normalize_retail_nation_economy,
    normalize_retail_province_loss,
    normalize_retail_province_ocean,
    normalize_retail_development,
    normalize_retail_yield_rebuild,
    normalize_retail_specialist_recruitment,
    normalize_retail_growth,
    normalize_retail_advisory,
    normalize_retail_battle_snapshots,
    normalize_retail_city_item_order,
    normalize_retail_opening,
    normalize_retail_pending_status,
    normalize_retail_news,
    normalize_retail_army_ui,
    normalize_retail_navy_ui,
    normalize_retail_reassess_missions,
    normalize_retail_recompute_metrics,
    normalize_retail_rng_contract,
    normalize_retail_military_phase,
    normalize_retail_military_phase_naval_tier_exhaustion,
    normalize_retail_strategic_naval_battle_matrix,
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


_COMPONENT_PROBE_SCENARIOS = frozenset(
    {
        "diplomacy_offer_gate",
        "quarter_gate_off_decade",
        "return_to_map_clears_notice_queues",
        "second_turn_military_cleanup",
        "strategic_naval_battle_matrix",
    }
)
_PRODUCTION_PATH_SCENARIOS = frozenset(
    {
        "elimination_phase_with_landed_great_powers",
        "military_phase_naval_encounter",
        "military_phase_naval_tier_exhaustion",
        "turn_state_combat_moves",
        "turn_state_ai_replan_perturbed",
        "turn_state_ai_reassess_damaged_ship",
        "turn_state_diplomacy_offer_gate",
        "turn_state_diplomacy_phase",
        "turn_state_military_cleanup",
        "turn_state_quarter_gate",
        "turn_state_return_to_map",
        "turn_stop_newspaper",
    }
)


def _scenario_classification(name: str) -> str:
    if name in _COMPONENT_PROBE_SCENARIOS:
        return "component_probe"
    if name in _PRODUCTION_PATH_SCENARIOS:
        return "production_path"
    return "unclassified"


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
        result_checkpoint_id={
            "military_phase_naval_encounter": CHECKPOINT_NAVAL_ENCOUNTER_PHASE,
            "military_phase_naval_escalation": CHECKPOINT_NAVAL_ESCALATION_PHASE,
            "military_phase_naval_tier_exhaustion": (
                CHECKPOINT_NAVAL_TIER_EXHAUSTION_PHASE
            ),
        }[name],
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
    elif name in (
        "military_phase_naval_encounter",
        "military_phase_naval_escalation",
        "military_phase_naval_tier_exhaustion",
    ):
        scenario = _military_phase_naval_encounter_scenario(fixture, name)
    elif name == "strategic_naval_battle_matrix":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes
            + (
                Probe(
                    probe_id="navy_trace.resolve_strategic_battle",
                    original_address=_RESOLVE_STRATEGIC_BATTLE,
                    fields={"receiver": FieldCapture("$ecx", "u32")},
                ),
            ),
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX,
        )
    elif name in ("military_phase_land_combat",
                  "military_phase_land_interactive",
                  "military_phase_land_retreat"):
        scenario = _military_phase_land_combat_scenario(fixture, name)
    elif name == "season_advance_clears_status_flags":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_SEASON_ADVANCE,
        )
    elif name == "elimination_phase_with_landed_great_powers":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_ELIMINATION_PHASE,
        )
    elif name == "turn_alerts_skip_first_economic_turn":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_TURN_ALERTS_FIRST,
        )
    elif name == "turn_alerts_later_turn":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_TURN_ALERTS_LATER,
        )
    elif name in (
        "great_power_pressure_human_debt",
        "great_power_pressure_ai_noop",
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_PRESSURE_HUMAN_DEBT
                if name == "great_power_pressure_human_debt"
                else CHECKPOINT_PRESSURE_AI_NOOP
            ),
        )
    elif name in (
        "interactive_army_battle_melee",
        "interactive_army_battle_ranged",
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=900,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_BATTLE_MELEE
                if name == "interactive_army_battle_melee"
                else CHECKPOINT_BATTLE_RANGED
            ),
        )
    elif name in (
        "combat_moves_uncontested",
        "combat_moves_creates_battle",
        "combat_moves_resumes_after_battle",
        "combat_moves_battle_then_later_movement",
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=900,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id={
                "combat_moves_uncontested": CHECKPOINT_COMBAT_UNCONTESTED,
                "combat_moves_creates_battle": CHECKPOINT_COMBAT_BATTLE,
                "combat_moves_resumes_after_battle": CHECKPOINT_COMBAT_RESUME,
                "combat_moves_battle_then_later_movement": (
                    CHECKPOINT_COMBAT_THEN_MOVES
                ),
            }[name],
        )
    elif name in (
        "navy_battle_accepted_deploy_tiles",
        "navy_battle_player_as_defender",
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=600,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_NAVY_BATTLE_DEPLOY
                if name == "navy_battle_accepted_deploy_tiles"
                else CHECKPOINT_NAVY_BATTLE_DEFENDER
            ),
        )
    elif name in ("turn_stop_deal_book", "turn_stop_city_and_transport"):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_TURN_STOP_DEAL_BOOK
                if name == "turn_stop_deal_book"
                else CHECKPOINT_TURN_STOP_CITY_TRANSPORT
            ),
        )
    elif name in _PLAYER_POLICY_ALL_SCENARIOS:
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=name + ".resolved",
        )
    elif name in (
        _NATION_ECONOMY_SCENARIOS
        + _DIPLOMACY_ECONOMY_SCENARIOS
        + _PROVINCE_SCENARIOS
        + _DEVELOPMENT_SCENARIOS
        + _YIELD_SCENARIOS
        + _GROWTH_SCENARIOS
        + _TACTICAL_SNAPSHOT_SCENARIOS
        + _ARMY_MILITARY_SCENARIOS
        + _CITY_ITEM_ORDER_SCENARIOS
        + _OPENING_SCENARIOS
        + _PENDING_STATUS_SCENARIOS
        + _NEWS_SCENARIOS
        + _ARMY_UI_SCENARIOS
        + _NAVY_UI_SCENARIOS
        + (
            "owned_region_development",
            "specialist_recruitment",
            "advisory_map_missions_case16",
        )
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=name + ".resolved",
        )
    elif name in ("turn_stop_technology", "turn_stop_trade"):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_TURN_STOP_TECHNOLOGY
                if name == "turn_stop_technology"
                else CHECKPOINT_TURN_STOP_TRADE
            ),
        )
    elif name in (
        "check_technology_advances",
        "check_technology_advances_ai_purchase",
        "technology_naval_capability_upgrade",
        "technology_naval_capability_sequence",
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_CHECK_TECH_ADVANCES
                if name == "check_technology_advances"
                else CHECKPOINT_CHECK_TECH_ADVANCES_AI
                if name == "check_technology_advances_ai_purchase"
                else CHECKPOINT_TECH_NAVAL_UPGRADE
                if name == "technology_naval_capability_upgrade"
                else CHECKPOINT_TECH_NAVAL_SEQUENCE
            ),
        )
    elif name == "consecutive_turn_sequence":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=600,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        )
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
    elif name == "turn_state_combat_moves":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=ACTION_TURN_STATE_COMBAT_MOVES,
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_TURN_STATE_COMBAT_MOVES,
        )
    elif name in (
        "turn_state_military_cleanup",
        "turn_state_ai_replan_perturbed",
        "turn_state_ai_reassess_damaged_ship",
    ):
        base = _load_save_to_map_scenario(fixture)
        if name == "turn_state_military_cleanup":
            action_id = ACTION_TURN_STATE_MILITARY_CLEANUP
            checkpoint_id = CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
        elif name == "turn_state_ai_replan_perturbed":
            action_id = ACTION_TURN_STATE_AI_REPLAN
            checkpoint_id = CHECKPOINT_TURN_STATE_AI_REPLAN
        else:
            action_id = ACTION_TURN_STATE_AI_REASSESS_DAMAGED
            checkpoint_id = CHECKPOINT_TURN_STATE_AI_REASSESS_DAMAGED
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=action_id,
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=checkpoint_id,
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
    elif name == "ai_naval_industry_development":
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        )
    elif name in (
        "reassess_control_sea_missions",
        "reassess_control_sea_missions_damaged_ship",
    ):
        base = _load_save_to_map_scenario(fixture)
        scenario = Scenario(
            name=name,
            native_test=name,
            action_id=name + ".run",
            fixture=fixture,
            probes=base.probes,
            terminal_checkpoint=base.terminal_checkpoint,
            timeout_seconds=base.timeout_seconds,
            start_action=base.start_action,
            drive=name,
            result_checkpoint_id=(
                CHECKPOINT_REASSESS_MISSIONS
                if name == "reassess_control_sea_missions"
                else CHECKPOINT_REASSESS_MISSIONS_DAMAGED
            ),
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


def _u8(session: GdbSession, address: int) -> int:
    return _eval_int(session, f"*(unsigned char*)0x{address:08x}") & 0xFF


def _s32(session: GdbSession, address: int) -> int:
    value = _eval_int(session, f"*(int*)0x{address:08x}") & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


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


def _seed_trade_market(
    session: GdbSession, active_nation: int, buy_clothing: bool = True
) -> None:
    """Mirror SeedMerchantCapacity + SeedTradeableStocks + SeedHumanTradeOrders:
    merchant-capacity order counts, city stocks, treasury, and the human's
    remembered trade offers / item potentials."""
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
    if buy_clothing:
        session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 13:08x}", -1)
        session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 2:08x}", 5)
    else:
        session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 13:08x}", 4)


def _drive_trade_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    stages: "dict[str, object] | None" = None,
    economic_turn: int | None = None,
    buy_clothing: bool = True,
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

    _seed_trade_market(session, active_nation, buy_clothing)

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
        aid_matrix = struct.unpack(
            "<368i", session.read_memory(nation + 0x280, 0x170 * 4)
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
                "diplomacy_eligibility": _u8(session, nation + 0xA0),
                "grant_total": _s32(session, nation + 0xAC),
                "need_current": list(
                    struct.unpack("<23h", session.read_memory(nation + 0x10E, 46))
                ),
                "need_target": list(
                    struct.unpack("<23h", session.read_memory(nation + 0x13C, 46))
                ),
                "relation_delta": list(
                    struct.unpack("<23h", session.read_memory(nation + 0x16A, 46))
                ),
                "budget_pool_base": _s32(session, nation + 0x840),
                "budget_pool_delta": _s32(session, nation + 0x844),
                "aid_allocation_total": _s32(session, nation + 0x914),
                "military_expenses": _s32(session, nation + 0x960),
                "aid_nonzero": [
                    [index, value]
                    for index, value in enumerate(aid_matrix)
                    if value != 0
                ],
                "city_stocks": city_stocks,
                "city_power_flag": (
                    _u8(session, city + 0x04) if city != 0 else None
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


def _u16(session: GdbSession, address: int) -> int:
    return _eval_int(session, f"*(unsigned short*)0x{address:08x}") & 0xFFFF


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


def _seed_city_transport(
    session: GdbSession, seed_pending_action: bool = True
) -> int:
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
    if seed_pending_action:
        session.assign(
            f"*(signed char*)0x{nation + 0x8C8 + 10:08x}", 0x32
        )
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
            "pending_payloads": list(
                struct.unpack("<13h", session.read_memory(nation + 0x8D6, 26))
            ),
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
        town_list = _u32(session, nation + 0x898)
        towns: list[dict[str, object]] = []
        if town_list != 0:
            for town in _sorted_ptr_list_entries(session, town_list):
                raw = session.read_memory(town, 0x50)
                towns.append(
                    {
                        "tile": struct.unpack("<h", raw[0x14:0x16])[0],
                        "owner": struct.unpack("<h", raw[0x1C:0x1E])[0],
                        "yields": list(
                            struct.unpack("<23h", raw[0x1E:0x4C])
                        ),
                        "transport_linked": 1 if raw[0x4C] else 0,
                        "enabled": raw[0x4D],
                        "adjacent_city": 1 if raw[0x4E] else 0,
                        "active": 1 if raw[0x4F] else 0,
                    }
                )
        nations.append(
            {
                "treasury": _eval_int(
                    session, f"*(int*)0x{nation + 0x10:08x}"
                ),
                "town_count": _town_marker_count(session, nation),
                "towns": towns,
                "home_tile": _s16(session, nation + 0x88),
                "city_stocks": (
                    list(
                        struct.unpack(
                            "<23h", session.read_memory(city + 0xB6, 46)
                        )
                    )
                    if city != 0
                    else None
                ),
                "order_counts": (
                    list(
                        struct.unpack(
                            "<14h", session.read_memory(city + 0x5C, 28)
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
_TSHIP_FREE = 0x0054F640
_TTASKFORCE_CTOR = 0x00552800
_TTASKFORCE_FREE = 0x00552930
_TTASKFORCE_SET_AGGRESSION = 0x00552F60
_TTASKFORCE_ADD = 0x00553BC0
_TTASKFORCE_ELECT_FLAGSHIP = 0x00553E30
_TTASKFORCE_SUBMIT_ORDERS = 0x005540B0
_RESOLVE_STRATEGIC_BATTLE = 0x0055A780
_ZONE_CREATE_TASK_FORCE = 0x005609E0
_TSHIP_SIZE = 0x38
_TTASKFORCE_SIZE = 0x34
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
    seen: set[int] = set()
    if list_pointer == 0:
        return entries
    node = _u32(session, list_pointer + 0x08)
    while node != 0:
        if node in seen:
            raise RuntimeError(
                f"TSortedList at 0x{list_pointer:08x} contains a node cycle"
            )
        seen.add(node)
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
                "defeated": raw[0x26] != 0,
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


# --- reassess_control_sea_missions retail drive --------------------------------
# Mirrors RunReassessControlSeaMissions: for each eligible TAutoGreatPower,
# iterate missionQueue and Reassess() entries that are both navy and hospital
# missions. TMission vtable slots: GetRuntimeClass 0x00 (CObject prefix),
# Reassess 0x10, IsNavyMission 0x15, IsHospitalMission 0x19.

_NATION_SLOT_ELIGIBLE = 0x00581280
_VT_MISSION_REASSESS = 0x10 * 4
_VT_MISSION_IS_NAVY = 0x15 * 4
_VT_MISSION_IS_HOSPITAL = 0x19 * 4
_NATION_MISSION_QUEUE = 0xB60


def _drive_reassess_missions(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        if (
            _runtime_class(
                session, nation, records, occurrences, breakpoint_roles
            )
            != _CLASS_AUTO_GREAT_POWER
        ):
            continue
        eligible = _invoke_thiscall(
            session,
            _NATION_SLOT_ELIGIBLE,
            sim_mgr,
            records,
            occurrences,
            breakpoint_roles,
            args=(slot,),
        )
        if eligible & 0xFF == 0:
            continue
        queue = _u32(session, nation + _NATION_MISSION_QUEUE)
        for mission in _sorted_ptr_list_entries(session, queue):
            if (
                _invoke_virtual(
                    session,
                    mission,
                    _VT_MISSION_IS_NAVY,
                    records,
                    occurrences,
                    breakpoint_roles,
                )
                & 0xFF
                == 0
            ):
                continue
            if (
                _invoke_virtual(
                    session,
                    mission,
                    _VT_MISSION_IS_HOSPITAL,
                    records,
                    occurrences,
                    breakpoint_roles,
                )
                & 0xFF
                == 0
            ):
                continue
            _invoke_virtual(
                session,
                mission,
                _VT_MISSION_REASSESS,
                records,
                occurrences,
                breakpoint_roles,
            )


def _read_cstring(session: GdbSession, address: int) -> str:
    if address == 0:
        return ""
    return session.read_memory(address, 64).split(b"\x00")[0].decode(
        "ascii", "replace"
    )


def _zone_ordinal(session: GdbSession, zone: int) -> int:
    return _s16(session, zone + 0x14) if zone != 0 else -1


def _capture_missions(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    missions: list[dict[str, object]] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        if (
            _runtime_class(
                session, nation, records, occurrences, breakpoint_roles
            )
            != _CLASS_AUTO_GREAT_POWER
        ):
            continue
        queue = _u32(session, nation + _NATION_MISSION_QUEUE)
        for mission in _sorted_ptr_list_entries(session, queue):
            raw = session.read_memory(mission, 0x3C)
            class_ptr = _runtime_class(
                session, mission, records, occurrences, breakpoint_roles
            )
            record: dict[str, object] = {
                "nation": slot,
                "kind": _read_cstring(
                    session, _u32(session, class_ptr) if class_ptr else 0
                ),
                "nation_id": struct.unpack("<h", raw[0x04:0x06])[0],
                "path_marker": struct.unpack("<h", raw[0x06:0x08])[0],
                "state": raw[0x08],
                "importance_bits": struct.unpack("<I", raw[0x0C:0x10])[0],
                "flag10": raw[0x10],
                "marker": raw[0x11],
            }
            if (
                _invoke_virtual(
                    session,
                    mission,
                    _VT_MISSION_IS_NAVY,
                    records,
                    occurrences,
                    breakpoint_roles,
                )
                & 0xFF
                != 0
            ):
                record["target_zone"] = _zone_ordinal(
                    session, struct.unpack("<I", raw[0x14:0x18])[0]
                )
                record["resolved_port_zone"] = _zone_ordinal(
                    session, struct.unpack("<I", raw[0x18:0x1C])[0]
                )
                record["navy_state"] = struct.unpack("<i", raw[0x28:0x2C])[0]
                record["has_orders"] = (
                    struct.unpack("<I", raw[0x24:0x28])[0] != 0
                )
                record["required_equipage_bits"] = [
                    struct.unpack("<I", raw[0x2C + i * 4 : 0x30 + i * 4])[0]
                    for i in range(4)
                ]
            missions.append(record)
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "missions": missions,
    }


# --- reassess_control_sea_missions_damaged_ship retail drive -------------------
# Mirrors RunReassessControlSeaMissionsDamagedShip: locate the first eligible
# auto nation's TControlSeaZoneMission (or construct one on the map-context
# head zone), force a war, park a hostile type-3 frigate at 899 strength in the
# target zone, then run the same reassessment walk.

_CONTROL_SEA_VTABLE = 0x0065A740
_TNAVY_MISSION_CTOR = 0x00535470
_MISSION_INIT_NATION = 0x005350A0
_TSORTED_LIST_ADD_TAIL = 0x00488610
_MISSION_SIZE = 0x3C
_TSHIP_STRENGTH = 0x1C


def _eligible_auto_nations(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> list[tuple[int, int]]:
    sim_mgr = _u32(session, _SIM_MGR)
    eligible: list[tuple[int, int]] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        if (
            _runtime_class(
                session, nation, records, occurrences, breakpoint_roles
            )
            != _CLASS_AUTO_GREAT_POWER
        ):
            continue
        if (
            _invoke_thiscall(
                session,
                _NATION_SLOT_ELIGIBLE,
                sim_mgr,
                records,
                occurrences,
                breakpoint_roles,
                args=(slot,),
            )
            & 0xFF
            == 0
        ):
            continue
        eligible.append((slot, nation))
    return eligible


def _mission_class_name(
    session: GdbSession,
    mission: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> str:
    class_ptr = _runtime_class(
        session, mission, records, occurrences, breakpoint_roles
    )
    return (
        _read_cstring(session, _u32(session, class_ptr)) if class_ptr else ""
    )


def _configure_reassess_missions_damaged(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    target_zone = 0
    mission_nation = -1
    for slot, nation in _eligible_auto_nations(
        session, records, occurrences, breakpoint_roles
    ):
        queue = _u32(session, nation + _NATION_MISSION_QUEUE)
        for mission in _sorted_ptr_list_entries(session, queue):
            if (
                _mission_class_name(
                    session, mission, records, occurrences, breakpoint_roles
                )
                == "TControlSeaZoneMission"
            ):
                target_zone = _u32(session, mission + 0x14)
                mission_nation = slot
                break
        if target_zone != 0:
            break
    if target_zone == 0:
        eligible = _eligible_auto_nations(
            session, records, occurrences, breakpoint_roles
        )
        if not eligible:
            raise RuntimeError("no eligible auto nation for the sea mission")
        mission_nation, nation = eligible[0]
        target_zone = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
        mission = _invoke_thiscall(
            session,
            _OPERATOR_NEW,
            0,
            records,
            occurrences,
            breakpoint_roles,
            args=(_MISSION_SIZE,),
        )
        _invoke_thiscall(
            session,
            _TNAVY_MISSION_CTOR,
            mission,
            records,
            occurrences,
            breakpoint_roles,
            args=(target_zone,),
        )
        session.assign(
            f"*(unsigned int*)0x{mission:08x}", _CONTROL_SEA_VTABLE
        )
        _invoke_thiscall(
            session,
            _MISSION_INIT_NATION,
            mission,
            records,
            occurrences,
            breakpoint_roles,
            args=(mission_nation,),
        )
        _invoke_thiscall(
            session,
            _TSORTED_LIST_ADD_TAIL,
            _u32(session, nation + _NATION_MISSION_QUEUE),
            records,
            occurrences,
            breakpoint_roles,
            args=(mission,),
        )
    hostile = 1 if mission_nation == 0 else 0
    _force_war_between(session, mission_nation, hostile)
    ship = _new_ship(
        session,
        3,
        target_zone,
        hostile,
        "damaged-hostile-frigate",
        records,
        occurrences,
        breakpoint_roles,
    )
    session.assign(f"*(short*)0x{ship + _TSHIP_STRENGTH:08x}", 899)
    return mission_nation


def _drive_reassess_missions_damaged(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    _configure_reassess_missions_damaged(
        session, records, occurrences, breakpoint_roles
    )
    _drive_reassess_missions(
        session, records, occurrences, breakpoint_roles
    )


# --- ai_naval_industry_development retail drive -------------------------------
# Mirrors RunAiNavalIndustryDevelopment: prime the first eligible auto nation's
# interior-minister order table, pin mission flag10, append a navyState=2
# TControlSeaZoneMission with 1000 equipment demand in slot 3, optionally
# reinforce it with a max-strength transport at a neighboring zone, then call
# TAutoGreatPower::PlanAiDevelopmentActionsFromResourcePools.

_PLAN_AI_DEVELOPMENT = 0x004EB190
_TSHIP_GET_MAX_STRENGTH = 0x005505A0
_VT_ACCEPT_REENFORCEMENT_SHIP = 0x21 * 4
_NATION_INTERIOR_MINISTER = 0x98
_MINISTER_ORDER_BA = 0xBA
_MINISTER_ORDER_DC = 0xDC
_MINISTER_LIST190 = 0x190
_ZONE_PRIMARY_NEIGHBORS = 0x24


def _configure_ai_naval_development_pressure(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    eligible = _eligible_auto_nations(
        session, records, occurrences, breakpoint_roles
    )
    head = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
    if not eligible or head == 0:
        raise RuntimeError("the fixture has no eligible AI-development nation")
    nation_slot, nation = eligible[0]
    minister = _u32(session, nation + _NATION_INTERIOR_MINISTER)
    for index in range(16):
        session.assign(
            f"*(short*)0x{minister + _MINISTER_ORDER_BA + index * 2:08x}", 20
        )
    queue = _u32(session, nation + _NATION_MISSION_QUEUE)
    for entry in _sorted_ptr_list_entries(session, queue):
        session.assign(f"*(char*)0x{entry + 0x10:08x}", 1)
    mission = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_MISSION_SIZE,),
    )
    _invoke_thiscall(
        session,
        _TNAVY_MISSION_CTOR,
        mission,
        records,
        occurrences,
        breakpoint_roles,
        args=(head,),
    )
    session.assign(f"*(unsigned int*)0x{mission:08x}", _CONTROL_SEA_VTABLE)
    _invoke_thiscall(
        session,
        _MISSION_INIT_NATION,
        mission,
        records,
        occurrences,
        breakpoint_roles,
        args=(nation_slot,),
    )
    session.assign(f"*(int*)0x{mission + 0x28:08x}", 2)
    for index, value in enumerate((0.0, 0.0, 0.0, 1000.0)):
        session.assign(
            f"*(float*)0x{mission + 0x2C + index * 4:08x}", repr(value)
        )
    session.assign(f"*(char*)0x{mission + 0x10:08x}", 0)
    _invoke_thiscall(
        session,
        _TSORTED_LIST_ADD_TAIL,
        queue,
        records,
        occurrences,
        breakpoint_roles,
        args=(mission,),
    )
    neighbor_count = _s32(session, head + _ZONE_PRIMARY_NEIGHBORS + 0x0C)
    if neighbor_count != 0:
        neighbor_data = _u32(session, head + _ZONE_PRIMARY_NEIGHBORS + 0x04)
        neighbor = _u32(session, neighbor_data)
        ship = _new_ship(
            session,
            4,
            neighbor,
            nation_slot,
            "naval-development-distance-weight",
            records,
            occurrences,
            breakpoint_roles,
        )
        max_strength = _invoke_thiscall(
            session,
            _TSHIP_GET_MAX_STRENGTH,
            ship,
            records,
            occurrences,
            breakpoint_roles,
        )
        # Sign-extend AX: GetMaxStrength returns short.
        max_strength = max_strength & 0xFFFF
        if max_strength >= 0x8000:
            max_strength -= 0x10000
        session.assign(
            f"*(short*)0x{ship + _TSHIP_STRENGTH:08x}", max_strength
        )
        _invoke_virtual(
            session,
            mission,
            _VT_ACCEPT_REENFORCEMENT_SHIP,
            records,
            occurrences,
            breakpoint_roles,
            args=(ship, 0),
        )
    return nation


def _drive_ai_naval_development(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    nation = _configure_ai_naval_development_pressure(
        session, records, occurrences, breakpoint_roles
    )
    _invoke_thiscall(
        session,
        _PLAN_AI_DEVELOPMENT,
        nation,
        records,
        occurrences,
        breakpoint_roles,
        args=(0,),
    )


def _long_list_entries(session: GdbSession, list_pointer: int) -> list[int]:
    """Walk a CList<long,long> node chain (m_pNodeHead at +0x04 after vptr)."""
    entries: list[int] = []
    if list_pointer == 0:
        return entries
    node = _u32(session, list_pointer + 0x04)
    while node != 0:
        entries.append(_s32(session, node + 8))
        node = _u32(session, node)
    return entries


def _capture_ai_development(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    capture = _capture_missions(
        session, records, occurrences, breakpoint_roles
    )
    development: list[dict[str, object]] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        if (
            _runtime_class(
                session, nation, records, occurrences, breakpoint_roles
            )
            != _CLASS_AUTO_GREAT_POWER
        ):
            continue
        minister = _u32(session, nation + _NATION_INTERIOR_MINISTER)
        if minister == 0:
            continue
        development.append(
            {
                "nation": slot,
                "order_ba": [
                    _s16(session, minister + _MINISTER_ORDER_BA + i * 2)
                    for i in range(16)
                ],
                "order_dc": [
                    _s16(session, minister + _MINISTER_ORDER_DC + i * 2)
                    for i in range(16)
                ],
                "queued_orders": _long_list_entries(
                    session, _u32(session, minister + _MINISTER_LIST190)
                ),
            }
        )
    capture["development"] = development
    return capture


# --- check_technology_advances retail drive ------------------------------------
# Mirrors RunCheckTechnologyAdvances: economicTurn=1234, tech 4 scheduled for
# that turn, every other unscheduled slot cleared, then
# TTechMgr::CheckForAdvances (0x5af980).

_CHECK_FOR_ADVANCES = 0x005AF980
_TECH_PRIORITY_SLOTS = 0x04
_TECH_UNLOCK_FLAGS = 0x180
_TECH_ENABLED_TYPES = 0x19D
_TECH_SELECTOR = 0x1D2
_TECH_ZONE_INDEX = 0x1D4
_TECH_MARKER = 0x262
_TECH_PREREQ_PAIR = 0x264
_TECH_ORDER_CAP_ROWS = 0x268
_TECH_ORDER_CAP_STRIDE = 0x1D
_TECH_ABILITY_ROWS = 0x395
_TECH_ABILITY_STRIDE = 0x1E
_TECH_UNIVERSITY_ROWS = 0x467
_TECH_UNIVERSITY_STRIDE = 9
_TECH_YEAR_ROWS = 0x4A6
_TECH_YEAR_STRIDE = 0x3A
_TECH_CAP_B_ROWS = 0x333
_TECH_CAP_B_STRIDE = 0x0E
_NATION_TREASURY = 0x10
_NATION_CITY = 0x894
_CITY_SHIP_ORDER_SLOTS = 0x190
_ORDER_RESOURCE_TYPE_INDEX = 0x48
_TADMIRAL_CTOR = 0x00551430
_TADMIRAL_ASSIGN_TO_SHIP = 0x00552250
_TADMIRAL_SIZE = 0x1C
_NAVY_SECONDARY_ORDER_LIST_HEAD = 0x006A3EBC
_TSHIP_SINK = 0x005509C0
_HANDLE_ABILITY_UNLOCK = 0x005AFD00
_TTECHMGR = 0x006A43D8
# Static MFC CreateObject sites (operator-new + inlined ctor + vptr store):
_NAVY_BATTLE_CREATE_OBJECT = 0x005A5480
_NAVY_HUMAN_PLAYER_CREATE_OBJECT = 0x0059EEF0
_NAVY_AUTO_PLAYER_CREATE_OBJECT = 0x0059F040
_TLIST_CREATE_OBJECT = 0x00487E50
_TNAVY_HUMAN_PLAYER_INIT = 0x0059EF90
_TNAVY_AUTO_PLAYER_INIT = 0x0059F0E0
_TNAVY_BATTLE_INIT = 0x005A5540
_TTACTICAL_BATTLE_DEPLOY_SLOT = 0x30
_TTACTICAL_BATTLE_FREE_SLOT = 0x1C
_TSORTED_LIST_ENTRY_BY_ORDINAL = 0x004886F0
_TTASKFORCE_SUBMIT_ORDERS = 0x005540B0
_TZONE_CREATE_TASK_FORCE = 0x005609E0
_TTACTICAL_TILE_RECORD_SIZE = 0x14
_TTASKFORCE_NATION = 0x1C


def _drive_check_technology_advances(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    tech_mgr = _u32(session, _TECH_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 1234)
    for tech in range(3, 0x1D):
        if tech == 4:
            continue
        if (
            _eval_int(
                session, f"*(unsigned char*)0x{tech_mgr + 0x180 + tech:08x}"
            )
            == 0
        ):
            session.assign(
                f"*(short*)0x{tech_mgr + _TECH_PRIORITY_SLOTS + 2 * tech:08x}",
                0,
            )
    session.assign(f"*(unsigned char*)0x{tech_mgr + 0x180 + 4:08x}", 0)
    session.assign(
        f"*(short*)0x{tech_mgr + _TECH_PRIORITY_SLOTS + 8:08x}", 1234
    )
    _invoke_thiscall(
        session,
        _CHECK_FOR_ADVANCES,
        tech_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _capture_technology(
    session: GdbSession,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    tech_mgr = _u32(session, _TECH_MGR)
    unlock_flags = list(
        session.read_memory(tech_mgr + _TECH_UNLOCK_FLAGS, 0x1D)
    )
    enabled_types = list(
        session.read_memory(tech_mgr + _TECH_ENABLED_TYPES, 0x0E)
    )
    nations: list[dict[str, object]] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        status = list(
            session.read_memory(
                tech_mgr + _TECH_ORDER_CAP_ROWS + slot * _TECH_ORDER_CAP_STRIDE,
                0x1D,
            )
        )
        years_raw = session.read_memory(
            tech_mgr + _TECH_YEAR_ROWS + slot * _TECH_YEAR_STRIDE, 0x3A
        )
        abilities = list(
            session.read_memory(
                tech_mgr + _TECH_ABILITY_ROWS + slot * _TECH_ABILITY_STRIDE,
                0x1E,
            )
        )
        university = list(
            session.read_memory(
                tech_mgr
                + _TECH_UNIVERSITY_ROWS
                + slot * _TECH_UNIVERSITY_STRIDE,
                9,
            )
        )
        nations.append(
            {
                "nation": slot,
                "treasury": _s32(session, nation + _NATION_TREASURY),
                "tech_status": status,
                "completion_years": [
                    struct.unpack("<h", years_raw[i * 2 : i * 2 + 2])[0]
                    for i in range(0x1D)
                ],
                "abilities": abilities,
                "university": university,
            }
        )
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "technology": {
            "marker": _s16(session, tech_mgr + _TECH_MARKER),
            "prereq_primary": _s16(session, tech_mgr + _TECH_PREREQ_PAIR),
            "prereq_secondary": _s16(
                session, tech_mgr + _TECH_PREREQ_PAIR + 2
            ),
            "selector": _s16(session, tech_mgr + _TECH_SELECTOR),
            "zone_index": _s16(session, tech_mgr + _TECH_ZONE_INDEX),
            "unlock_flags": unlock_flags,
            "enabled_types": enabled_types,
            "nations": nations,
            "cap_b_selected": [
                list(
                    session.read_memory(
                        tech_mgr + _TECH_CAP_B_ROWS + slot * _TECH_CAP_B_STRIDE,
                        0x0E,
                    )
                )
                for slot in range(_MAJOR_NATION_COUNT)
            ],
            "ship_order_types": _capture_ship_order_types(session),
            "ships": _capture_navy_ships(session),
            "admirals": _capture_navy_admirals(session),
        },
    }


def _navy_ship_list(session: GdbSession) -> list[int]:
    ships: list[int] = []
    ship = _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD)
    while ship != 0:
        ships.append(ship)
        ship = _u32(session, ship + 0x24)
    return ships


def _capture_navy_ships(session: GdbSession) -> list[dict[str, object]]:
    return [
        {
            "nation": _s16(session, ship + 0x14),
            "type": _s16(session, ship + 0x04),
            "strength": _s16(session, ship + 0x1C),
            "experience": _s16(session, ship + 0x30),
        }
        for ship in _navy_ship_list(session)
    ]


def _capture_navy_admirals(session: GdbSession) -> list[dict[str, object]]:
    ships = _navy_ship_list(session)
    admirals: list[dict[str, object]] = []
    admiral = _u32(session, _NAVY_SECONDARY_ORDER_LIST_HEAD)
    while admiral != 0:
        assigned = _u32(session, admiral + 0x08)
        admirals.append(
            {
                "nation": _s16(session, admiral + 0x04),
                "experience": _s16(session, admiral + 0x10),
                "ship": ships.index(assigned) if assigned in ships else -1,
            }
        )
        admiral = _u32(session, admiral + 0x14)
    return admirals


def _capture_ship_order_types(session: GdbSession) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        city = _u32(session, nation + _NATION_CITY)
        if city == 0:
            continue
        types = []
        for order_slot in range(8):
            order = _u32(
                session, city + _CITY_SHIP_ORDER_SLOTS + order_slot * 4
            )
            types.append(_s16(session, order + _ORDER_RESOURCE_TYPE_INDEX))
        records.append({"nation": slot, "types": types})
    return records


def _drive_technology_naval_capability_upgrade(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    technology_ids: tuple[int, ...] = (9,),
    with_ships: bool = True,
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    tech_mgr = _u32(session, _TTECHMGR)
    active_nation = _s16(session, sim_mgr + 0x2E)
    nation_slot = 1 if active_nation == 0 else 0
    nation = _nation_pointer(session, nation_slot)
    if nation == 0:
        raise RuntimeError("naval-upgrade fixture has no target nation")
    city = _u32(session, nation + _NATION_CITY)
    zone = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
    if city == 0 or zone == 0:
        raise RuntimeError("naval-upgrade fixture lacks city or zone")

    # ClearNationNavy: free the nation's admirals, then sink its ships.
    admiral = _u32(session, _NAVY_SECONDARY_ORDER_LIST_HEAD)
    while admiral != 0:
        next_admiral = _u32(session, admiral + 0x14)
        if _s16(session, admiral + 0x04) == nation_slot:
            _invoke_virtual(
                session,
                admiral,
                0x1C,
                records,
                occurrences,
                breakpoint_roles,
            )
        admiral = next_admiral
    ship = _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD)
    while ship != 0:
        next_ship = _u32(session, ship + 0x24)
        if _s16(session, ship + 0x14) == nation_slot:
            _invoke_thiscall(
                session,
                _TSHIP_SINK,
                ship,
                records,
                occurrences,
                breakpoint_roles,
            )
        ship = next_ship

    cap_b_base = tech_mgr + _TECH_CAP_B_ROWS + nation_slot * _TECH_CAP_B_STRIDE
    for resource_type in range(0x0E):
        session.assign(
            f"*(unsigned char*)0x{cap_b_base + resource_type:08x}",
            1 if resource_type < 5 else 0,
        )
    for order_slot, ship_type in enumerate((1, 2, 0, 0, 3, 4, 0, 0)):
        order = _u32(
            session, city + _CITY_SHIP_ORDER_SLOTS + order_slot * 4
        )
        session.assign(
            f"*(short*)0x{order + _ORDER_RESOURCE_TYPE_INDEX:08x}",
            ship_type,
        )

    if with_ships:
        survivor_a = _new_ship(
            session,
            3,
            zone,
            nation_slot,
            "technology-survivor-a",
            records,
            occurrences,
            breakpoint_roles,
        )
        session.assign(f"*(short*)0x{survivor_a + 0x30:08x}", 100)
        survivor_b = _new_ship(
            session,
            4,
            zone,
            nation_slot,
            "technology-survivor-b",
            records,
            occurrences,
            breakpoint_roles,
        )
        session.assign(f"*(short*)0x{survivor_b + 0x30:08x}", 498)
        obsolete = _new_ship(
            session,
            1,
            zone,
            nation_slot,
            "technology-obsolete",
            records,
            occurrences,
            breakpoint_roles,
        )
        session.assign(f"*(short*)0x{obsolete + 0x30:08x}", 250)

        admiral_ptr = _invoke_thiscall(
            session,
            _OPERATOR_NEW,
            0,
            records,
            occurrences,
            breakpoint_roles,
            args=(_TADMIRAL_SIZE,),
        )
        _invoke_thiscall(
            session,
            _TADMIRAL_CTOR,
            admiral_ptr,
            records,
            occurrences,
            breakpoint_roles,
            args=(nation_slot,),
        )
        admiral_name = _write_name_string(
            session,
            "technology-admiral",
            records,
            occurrences,
            breakpoint_roles,
        )
        session.assign(f"*(int*)0x{admiral_ptr + 0x0C:08x}", admiral_name)
        session.assign(f"*(short*)0x{admiral_ptr + 0x10:08x}", 200)
        _invoke_thiscall(
            session,
            _TADMIRAL_ASSIGN_TO_SHIP,
            admiral_ptr,
            records,
            occurrences,
            breakpoint_roles,
            args=(obsolete,),
        )

    for index, technology_id in enumerate(technology_ids):
        session.assign(
            f"*(unsigned char*)0x{tech_mgr + _TECH_ORDER_CAP_ROWS + nation_slot * _TECH_ORDER_CAP_STRIDE + technology_id:08x}",
            1,
        )
        session.assign(
            f"*(short*)0x{tech_mgr + _TECH_YEAR_ROWS + nation_slot * _TECH_YEAR_STRIDE + 2 * technology_id:08x}",
            70 + index if len(technology_ids) > 1 else 77,
        )
    for technology_id in technology_ids:
        _invoke_thiscall(
            session,
            _HANDLE_ABILITY_UNLOCK,
            tech_mgr,
            records,
            occurrences,
            breakpoint_roles,
            args=(technology_id, nation_slot),
        )


def _navy_zone_unoccupied(session: GdbSession, zone: int) -> bool:
    ship = _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD)
    while ship != 0:
        if _u32(session, ship + 0x08) == zone:
            return False
        ship = _u32(session, ship + 0x24)
    return True


def _find_unoccupied_map_zone(session: GdbSession) -> int:
    zone = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
    while zone != 0:
        if _navy_zone_unoccupied(session, zone):
            return zone
        zone = _u32(session, zone + 0x18)
    return 0


def _create_frigate_force(
    session: GdbSession,
    zone: int,
    nation_slot: int,
    orders: int,
    order_target: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    for _ in range(2):
        _new_ship(
            session,
            3,
            zone,
            nation_slot,
            "navy-tactical",
            records,
            occurrences,
            breakpoint_roles,
        )
    force = _invoke_thiscall(
        session,
        _TZONE_CREATE_TASK_FORCE,
        zone,
        records,
        occurrences,
        breakpoint_roles,
        args=(nation_slot,),
    )
    if force != 0:
        _invoke_thiscall(
            session,
            _TTASKFORCE_SUBMIT_ORDERS,
            force,
            records,
            occurrences,
            breakpoint_roles,
            args=(orders, order_target),
        )
    return force


def _navy_deploy_probe_tiles(
    session: GdbSession,
    battle: int,
    unit: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> list[int]:
    tiles: list[int] = []
    if unit == 0:
        return tiles
    side = _s32(session, unit + 0x20)
    player = _u32(session, battle + 0x14 + side * 4)
    saved_tile = _s32(session, unit + 0x08)
    saved_ready = _u8(session, player + 0x10)
    saved_cursor = _s32(session, player + 0x18)
    saved_selected = _u32(session, battle + 0x1C)
    saved_side = _s32(session, battle + 0x0C)
    saved_live = _s32(session, battle + 0x10)
    tile_grid = _u32(session, battle + 0x04)
    tile_count = _s32(session, battle + 0x3C)
    for tile in range(tile_count):
        occupant = _u32(
            session, tile_grid + tile * _TTACTICAL_TILE_RECORD_SIZE + 0x04
        )
        _invoke_virtual(
            session,
            battle,
            _TTACTICAL_BATTLE_DEPLOY_SLOT,
            records,
            occurrences,
            breakpoint_roles,
            args=(unit, tile),
        )
        if _s32(session, unit + 0x08) == tile:
            tiles.append(tile)
            session.assign(f"*(int*)0x{unit + 0x08:08x}", saved_tile)
            session.assign(
                f"*(int*)0x{tile_grid + tile * _TTACTICAL_TILE_RECORD_SIZE + 0x04:08x}",
                occupant,
            )
            session.assign(f"*(unsigned char*)0x{player + 0x10:08x}", saved_ready)
            session.assign(f"*(int*)0x{player + 0x18:08x}", saved_cursor)
            session.assign(f"*(int*)0x{battle + 0x1C:08x}", saved_selected)
            session.assign(f"*(int*)0x{battle + 0x0C:08x}", saved_side)
            session.assign(f"*(int*)0x{battle + 0x10:08x}", saved_live)
    return tiles


def _drive_navy_battle_deploy(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    defender_is_active: bool,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_nation = _s16(session, sim_mgr + 0x2E)
    hostile_nation = -1
    for slot in range(_MAJOR_NATION_COUNT):
        if slot != active_nation and _nation_pointer(session, slot) != 0:
            hostile_nation = slot
            break
    zone = _find_unoccupied_map_zone(session)
    if hostile_nation < 0 or zone == 0:
        raise RuntimeError("fixture cannot create a naval tactical battle")

    attacker_nation = active_nation if not defender_is_active else hostile_nation
    defender_nation = hostile_nation if not defender_is_active else active_nation
    attacker = _create_frigate_force(
        session,
        zone,
        attacker_nation,
        3,
        0,
        records,
        occurrences,
        breakpoint_roles,
    )
    defender = _create_frigate_force(
        session,
        zone,
        defender_nation,
        6,
        zone,
        records,
        occurrences,
        breakpoint_roles,
    )
    if attacker == 0 or defender == 0:
        raise RuntimeError("could not create the naval task forces")
    _force_war_between(session, active_nation, hostile_nation)

    our_force = defender if defender_is_active else attacker
    enemy_force = attacker if defender_is_active else defender
    our_nation = _s16(session, our_force + _TTASKFORCE_NATION)
    enemy_nation = _s16(session, enemy_force + _TTASKFORCE_NATION)

    battle = _invoke_thiscall(
        session,
        _NAVY_BATTLE_CREATE_OBJECT,
        0,
        records,
        occurrences,
        breakpoint_roles,
    )
    session.assign(
        f"*(int*)0x{battle + 0x20:08x}",
        _invoke_thiscall(
            session,
            _TLIST_CREATE_OBJECT,
            0,
            records,
            occurrences,
            breakpoint_roles,
        ),
    )
    our_player = _invoke_thiscall(
        session,
        _NAVY_HUMAN_PLAYER_CREATE_OBJECT,
        0,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _TNAVY_HUMAN_PLAYER_INIT,
        our_player,
        records,
        occurrences,
        breakpoint_roles,
        args=(our_force, 1, our_nation),
    )
    session.assign(
        f"*(int*)0x{our_player + 0x08:08x}",
        _invoke_thiscall(
            session,
            _TLIST_CREATE_OBJECT,
            0,
            records,
            occurrences,
            breakpoint_roles,
        ),
    )
    enemy_player = _invoke_thiscall(
        session,
        _NAVY_AUTO_PLAYER_CREATE_OBJECT,
        0,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _TNAVY_AUTO_PLAYER_INIT,
        enemy_player,
        records,
        occurrences,
        breakpoint_roles,
        args=(enemy_force, 0, enemy_nation),
    )
    session.assign(
        f"*(int*)0x{enemy_player + 0x08:08x}",
        _invoke_thiscall(
            session,
            _TLIST_CREATE_OBJECT,
            0,
            records,
            occurrences,
            breakpoint_roles,
        ),
    )
    _invoke_thiscall(
        session,
        _TNAVY_BATTLE_INIT,
        battle,
        records,
        occurrences,
        breakpoint_roles,
        args=(our_player, enemy_player),
    )

    our_unit_list = _u32(session, our_player + 0x04)
    enemy_unit_list = _u32(session, enemy_player + 0x04)
    side0_unit = _invoke_thiscall(
        session,
        _TSORTED_LIST_ENTRY_BY_ORDINAL,
        our_unit_list,
        records,
        occurrences,
        breakpoint_roles,
        args=(1,),
    )
    side1_unit = _invoke_thiscall(
        session,
        _TSORTED_LIST_ENTRY_BY_ORDINAL,
        enemy_unit_list,
        records,
        occurrences,
        breakpoint_roles,
        args=(1,),
    )
    side0_tiles = _navy_deploy_probe_tiles(
        session, battle, side0_unit, records, occurrences, breakpoint_roles
    )
    side1_tiles = _navy_deploy_probe_tiles(
        session, battle, side1_unit, records, occurrences, breakpoint_roles
    )

    snapshot = {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "column_count": _s32(session, battle + 0x34),
        "current_side": _s32(session, battle + 0x0C),
        "side0_nation": _s32(session, our_player + 0x1C),
        "side1_nation": _s32(session, enemy_player + 0x1C),
        "side0_selected": _u8(session, side0_unit + 0x18) if side0_unit else 0,
        "side1_selected": _u8(session, side1_unit + 0x18) if side1_unit else 0,
        "side0_tiles": side0_tiles,
        "side1_tiles": side1_tiles,
    }
    _invoke_virtual(
        session,
        battle,
        _TTACTICAL_BATTLE_FREE_SLOT,
        records,
        occurrences,
        breakpoint_roles,
    )
    return snapshot


def _drive_check_technology_advances_ai_purchase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    """Mirror RunCheckTechnologyAdvancesAiPurchase: economicTurn=1, every tech
    cleared for the AI slot except tech 3 (researched globally, pending for the
    AI), eligibility zeroed, treasury pinned at 50000, then CheckForAdvances."""
    sim_mgr = _u32(session, _SIM_MGR)
    tech_mgr = _u32(session, _TECH_MGR)
    active_nation = _s16(session, sim_mgr + 0x2E)
    ai_slot = 1 if active_nation == 0 else 0
    ai_nation = _nation_pointer(session, ai_slot)
    if ai_nation == 0:
        raise RuntimeError("the fixture has no AI great-power slot")
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 1)
    for tech in range(3, 0x1D):
        session.assign(
            f"*(unsigned char*)0x{tech_mgr + _TECH_UNLOCK_FLAGS + tech:08x}", 0
        )
        session.assign(
            f"*(short*)0x{tech_mgr + _TECH_PRIORITY_SLOTS + 2 * tech:08x}", 0
        )
        session.assign(
            f"*(unsigned char*)0x{tech_mgr + _TECH_ORDER_CAP_ROWS + ai_slot * _TECH_ORDER_CAP_STRIDE + tech:08x}",
            2,
        )
    session.assign(f"*(unsigned char*)0x{tech_mgr + _TECH_UNLOCK_FLAGS + 3:08x}", 1)
    session.assign(
        f"*(unsigned char*)0x{tech_mgr + _TECH_ORDER_CAP_ROWS + ai_slot * _TECH_ORDER_CAP_STRIDE + 3:08x}",
        0,
    )
    session.assign(f"*(unsigned char*)0x{ai_nation + 0xA0:08x}", 0)
    session.assign(f"*(int*)0x{ai_nation + _NATION_TREASURY:08x}", 50000)
    _invoke_thiscall(
        session,
        _CHECK_FOR_ADVANCES,
        tech_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _drive_turn_stop_technology(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    """Mirror RunTechnologyTurnStop: clear every unscheduled unlock, mark tech 3
    pending for the active nation, enter turn state 0x11, and step
    AdvanceGlobalTurnStateMachine once."""
    sim_mgr = _u32(session, _SIM_MGR)
    tech_mgr = _u32(session, _TECH_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 1)
    for tech in range(3, 0x1D):
        if (
            _eval_int(
                session, f"*(unsigned char*)0x{tech_mgr + 0x180 + tech:08x}"
            )
            == 0
        ):
            session.assign(
                f"*(short*)0x{tech_mgr + _TECH_PRIORITY_SLOTS + 2 * tech:08x}",
                0,
            )
    active_nation = _s16(session, sim_mgr + 0x2E)
    session.assign(
        f"*(unsigned char*)0x{tech_mgr + _TECH_ORDER_CAP_ROWS + active_nation * _TECH_ORDER_CAP_STRIDE + 3:08x}",
        1,
    )
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x11)
    _invoke_thiscall(
        session,
        _ADVANCE_TURN_STATE,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


# --- turn_stop_trade retail drive -----------------------------------------------
# Mirrors RunTradeTurnStop: seed the trade market, enter turnStateCode 7, and
# step AdvanceGlobalTurnStateMachine until it poses the Offer Sheet dialog.

_DISPLAY_MGR = 0x006A2158
_CONTROL_TAG_MAIN = 0x6D61696E  # 'main'
# TView::ResolveControlByTag -- vtable index 0x25 -> byte offset 0x94.
_VT_RESOLVE_CONTROL_BY_TAG = 0x25 * 4


def _drive_turn_stop_trade(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    trade_mgr = _u32(session, _TRADE_MGR)
    active_nation = _nation_pointer(session, _s16(session, sim_mgr + 0x2E))
    if active_nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    if (
        _eval_int(session, f"*(unsigned int*)0x{active_nation + 0x894:08x}")
        == 0
        or _eval_int(
            session, f"*(unsigned char*)0x{active_nation + 0xA0:08x}"
        )
        == 0
    ):
        raise RuntimeError(
            "the active nation cannot receive trade offers"
        )
    _seed_trade_market(session, active_nation)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 7)
    _invoke_thiscall(
        session, _SRAND, 0, records, occurrences, breakpoint_roles,
        args=(0x1234,)
    )
    _invoke_thiscall(
        session,
        _ADVANCE_TURN_STATE,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    display_mgr = _u32(session, _DISPLAY_MGR)
    dialog = _u32(session, display_mgr + 0x04)
    sheet = 0
    if dialog != 0:
        sheet = _invoke_virtual(
            session,
            dialog,
            _VT_RESOLVE_CONTROL_BY_TAG,
            records,
            occurrences,
            breakpoint_roles,
            args=(_CONTROL_TAG_MAIN,),
        )
    if sheet == 0 or _s16(session, sheet + 0x90) < 0:
        raise RuntimeError("trade phase did not pose an Offer Sheet")
    row0 = trade_mgr + _TRADE_ROW_BASE
    category_index = _s16(session, row0)
    # g_aTradeDealCategoryOrder_0066D810 at 0x66d810: order index -> category.
    # Capture the first-processed category (clothing) regardless of where the
    # deal cursor stopped.
    dispatch_idx = _s16(session, 0x0066D810)
    deal_list = _u32(session, trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch_idx)
    deals = []
    deal_data = _u32(session, deal_list + 0x04)  # CPtrArray::m_pData
    deal_count = _eval_int(
        session, f"*(int*)0x{deal_list + 0x08:08x}"
    )  # CPtrArray::m_nSize
    for ordinal in range(deal_count):
        deal = _u32(session, deal_data + 4 * ordinal)
        deals.append(
            {
                "source": _s16(session, deal),
                "target": _s16(session, deal + 0x02),
                "delta": _s16(session, deal + 0x04),
                "standing": _s16(session, deal + 0x06),
                "score": _eval_int(
                    session, f"*(int*)0x{deal + 0x08:08x}"
                ),
            }
        )
    result = _capture_turn_state(session)
    result.update(
        {
            "stop": "trade_offer",
            "phase": _eval_int(
                session, f"*(int*)0x{sim_mgr + 0x04:08x}"
            ),
            "category_index": category_index,
            "entry_ordinal": _s16(session, row0 + 2),
            "buyer": _s16(session, sheet + 0x90),
            "seller": _s16(session, sheet + 0x92),
            "amount": _s16(session, sheet + 0x98),
            "price": _s16(session, sheet + 0x94),
            "commodity": _s16(session, sheet + 0x96),
            "deals": deals,
        }
    )
    return result


# --- player_diplomacy_policy_* retail drives ------------------------------------
# Mirrors TogglePlayerDiplomacyPolicyResult in NativeDiplomacyCases.cpp: each case
# seeds relation/mission matrix pairs or nation fields, then runs the same
# validate -> entanglement-guard -> apply sequence against the real functions.

# TDiplomacyMgr field offsets (shorts over kNationPairMatrixEntries = 23*23).
_DIPLO_REL_PROPAGATION = 0x0BBE   # relationPropagationMatrix
_DIPLO_REL_TURN_STAMP = 0x0FE0    # relationTurnStampMatrix
_DIPLO_REL_SIDE_EFFECT = 0x1402   # relationSideEffectMatrix
_DIPLO_PROPOSAL_MODE = 0x18D8     # proposalArrayMode

# TGreatPower field offsets.
_GNATION_SLOT = 0x0C              # TCountry::nationSlot
_GNATION_GRANT_TOTAL = 0xAC       # grantTotalCost
_GNATION_POLICIES = 0xB2          # diplomacyPolicyByNation[23]
_GNATION_BUDGET_BASE = 0x8F0      # diplomacyBudgetBase
_TERRAIN_ENCODED_SLOT = 0x0E      # TCountry::encodedNationSlot

# Direct body addresses -- the active nation is always a human TGreatPower, so
# the TGreatPower override is the correct target for the Apply/Grant virtuals.
_FN_VALIDATE_DIPLO_ACTION = 0x004EF700  # ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode
_FN_HAS_ALLIANCE_GUARD = 0x004EFC30     # HasAllianceGuardForNationPair
_FN_APPLY_DIPLO_POLICY = 0x004DDFC0     # ApplyDiplomacyPolicyStateForTargetWithCostChecks
_FN_SET_DIPLO_GRANT = 0x004DE340        # SetDiplomacyGrantEntryForTargetAndUpdateTreasury

# Relationship codes (DiplomacyRelationshipStorage).
_REL_ALLIANCE = 2
_REL_PEACE = 4
_REL_WAR = 6

# Policy codes.
_POLICY_JOIN_EMPIRE = 0x12D
_POLICY_ALLIANCE = 0x12E
_POLICY_NON_AGGRESSION = 0x12F
_POLICY_PEACE_TREATY = 0x130
_POLICY_DECLARE_WAR = 0x131
_POLICY_CONSULATE = 0x133
_POLICY_EMBASSY = 0x134


def _dip_matrix_pair_write(
    session: GdbSession,
    diplo: int,
    base: int,
    a: int,
    b: int,
    value: int,
) -> None:
    session.assign(
        f"*(short*)0x{diplo + base + 2 * (a * _NATION_SLOT_COUNT + b):08x}",
        value,
    )
    session.assign(
        f"*(short*)0x{diplo + base + 2 * (b * _NATION_SLOT_COUNT + a):08x}",
        value,
    )


def _dip_set_relation(
    session: GdbSession,
    diplo: int,
    a: int,
    b: int,
    relation: int,
    stamp: int = -1,
) -> None:
    _dip_matrix_pair_write(
        session, diplo, _DIPLO_REL_PROPAGATION, a, b, relation
    )
    _dip_matrix_pair_write(
        session, diplo, _DIPLO_REL_TURN_STAMP, a, b, stamp
    )


def _dip_set_mission(
    session: GdbSession, diplo: int, a: int, b: int, level: int
) -> None:
    _dip_matrix_pair_write(
        session, diplo, _DIPLO_REL_SIDE_EFFECT, a, b, level
    )


def _diplomacy_mgr(session: GdbSession) -> int:
    return _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")


def _toggle_player_policy(
    session: GdbSession,
    nation: int,
    diplo: int,
    target: int,
    policy: int,
    action: int,
    confirm_entanglements: bool,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    bool_result: bool = False,
) -> int:
    """Mirror TogglePlayerDiplomacyPolicyResult (or the 4-arg bool variant when
    bool_result is set) through the real functions."""
    nation_slot = _s16(session, nation + _GNATION_SLOT)
    if not bool_result and nation_slot == target:
        return 3
    if _s16(session, nation + _GNATION_POLICIES + 2 * target) == policy:
        applied = _invoke_thiscall(
            session,
            _FN_APPLY_DIPLO_POLICY,
            nation,
            records,
            occurrences,
            breakpoint_roles,
            args=(target, -1),
        ) & 0xFF
        return 1 if applied else 0
    valid = _invoke_thiscall(
        session,
        _FN_VALIDATE_DIPLO_ACTION,
        diplo,
        records,
        occurrences,
        breakpoint_roles,
        args=(nation_slot, target, action),
    ) & 0xFF
    if not valid:
        if bool_result:
            return 0
        return -_s16(session, diplo + _DIPLO_PROPOSAL_MODE)
    if (
        not bool_result
        and not confirm_entanglements
        and action in (2, 3)
        and _invoke_thiscall(
            session,
            _FN_HAS_ALLIANCE_GUARD,
            diplo,
            records,
            occurrences,
            breakpoint_roles,
            args=(target, nation_slot),
        )
        & 0xFF
    ):
        return 2
    applied = _invoke_thiscall(
        session,
        _FN_APPLY_DIPLO_POLICY,
        nation,
        records,
        occurrences,
        breakpoint_roles,
        args=(target, policy),
    ) & 0xFF
    return 1 if applied else 0


# Per-case spec: (target selector, setup ops, policy, action, confirm).
# Selectors: "minor" = slot 7, "m1"/"m2" = other majors, "self" = the source.
# Setup ops use symbolic slots resolved against the active nation:
#   ("mission", a, b, level)        -> symmetric side-effect matrix write
#   ("rel", a, b, relation[, stamp])-> symmetric propagation + turn-stamp write
#   ("grant", target, amount)       -> SetDiplomacyGrantEntryForTargetAndUpdateTreasury
#   ("treasury", value)             -> treasuryValue10
#   ("budget", value)               -> diplomacyBudgetBase
#   ("grant_total", value)          -> grantTotalCost
#   ("policy", target, code)        -> diplomacyPolicyByNation[target]
#   ("colony", target, owner)       -> terrain[target].encodedNationSlot = 200+owner
_PLAYER_DIPLO_POLICY_SPECS: dict[str, tuple] = {
    "player_diplomacy_policy_posts_consulate": (
        "minor", (), _POLICY_CONSULATE, 14, False, True
    ),
    "player_diplomacy_policy_rejects_consulate_on_major": (
        "m1", (), _POLICY_CONSULATE, 14, False, True
    ),
    "player_diplomacy_policy_posts_join_empire": (
        "minor",
        (("mission", "s", "t", 2), ("rel", "s", "t", _REL_PEACE)),
        _POLICY_JOIN_EMPIRE,
        2,
        False,
    ),
    "player_diplomacy_policy_posts_alliance": (
        "m1",
        (("mission", "s", "t", 2), ("rel", "s", "t", _REL_PEACE)),
        _POLICY_ALLIANCE,
        3,
        False,
    ),
    "player_diplomacy_policy_needs_alliance_entanglement": (
        "m1",
        (
            ("mission", "s", "t", 2),
            ("rel", "s", "t", _REL_PEACE),
            ("rel", "m1", "m2", _REL_WAR),
        ),
        _POLICY_ALLIANCE,
        3,
        False,
    ),
    "player_diplomacy_policy_confirms_alliance_entanglement": (
        "m1",
        (
            ("mission", "s", "t", 2),
            ("rel", "s", "t", _REL_PEACE),
            ("rel", "m1", "m2", _REL_WAR),
        ),
        _POLICY_ALLIANCE,
        3,
        True,
    ),
    "player_diplomacy_policy_posts_non_aggression_pact": (
        "minor",
        (("mission", "s", "t", 2), ("rel", "s", "t", _REL_PEACE)),
        _POLICY_NON_AGGRESSION,
        4,
        False,
    ),
    "player_diplomacy_policy_posts_peace_treaty": (
        "m1",
        (("rel", "s", "t", _REL_WAR),),
        _POLICY_PEACE_TREATY,
        5,
        False,
    ),
    "player_diplomacy_policy_posts_declare_war": (
        "m1",
        (("rel", "s", "t", _REL_ALLIANCE), ("grant", "t", 1000)),
        _POLICY_DECLARE_WAR,
        6,
        False,
    ),
    "player_diplomacy_policy_posts_embassy": (
        "minor",
        (("mission", "s", "t", 1), ("rel", "s", "t", _REL_PEACE)),
        _POLICY_EMBASSY,
        15,
        False,
    ),
    "player_diplomacy_policy_retracts_embassy": (
        "minor",
        (("policy", "t", _POLICY_EMBASSY),),
        _POLICY_EMBASSY,
        15,
        False,
    ),
    "player_diplomacy_policy_cannot_afford_committed_consulate": (
        "minor",
        (
            ("mission", "s", "t", 0),
            ("rel", "s", "t", _REL_PEACE),
            ("treasury", 500),
            ("budget", 0),
            ("grant_total", 1),
        ),
        _POLICY_CONSULATE,
        14,
        False,
    ),
    "player_diplomacy_policy_rejects_colony": (
        "minor",
        (("colony", "t", "m1"),),
        _POLICY_DECLARE_WAR,
        6,
        False,
    ),
    "player_diplomacy_policy_selects_self": (
        "self", (), _POLICY_ALLIANCE, 3, False
    ),
}

# Trade-policy tails mirror TogglePlayerTradePolicyResult: validate the boycott
# or subsidy action, then SetTradePolicyTo(target, need==value ? 100 : value).
_PLAYER_TRADE_POLICY_SPECS: dict[str, tuple] = {
    "player_trade_policy_posts_subsidy": (
        "minor",
        (("mission", "s", "t", 1),),
        95,
    ),
    "player_trade_policy_retracts_subsidy": (
        "minor",
        (("mission", "s", "t", 1), ("need", "t", 95)),
        95,
    ),
    "player_trade_policy_boycott_clears_grant": (
        "m1",
        (("grant", "t", 1000),),
        300,
    ),
    "player_trade_policy_rejects_allied_boycott": (
        "m1",
        (("rel", "s", "t", _REL_ALLIANCE),),
        300,
    ),
}

# Colony-boycott tails mirror RunConfiguredPlayerColonyBoycott: decode the
# target's controlling nation and toggle the boycott flag through the real
# SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations.
_PLAYER_COLONY_BOYCOTT_SPECS: dict[str, tuple] = {
    "player_colony_boycott_posts_and_propagates": (
        "m1",
        (("colony", "minor", "s"),),
    ),
    "player_colony_boycott_retracts_and_propagates": (
        "m1",
        (
            ("colony", "minor", "s"),
            ("boycott", "t", 1),
            ("colony_trade", "minor", "t", 300),
        ),
    ),
    "player_colony_boycott_own_colony_no_op": (
        "minor",
        (("colony", "t", "s"),),
    ),
}

_PLAYER_TRADE_BOYCOTT_SCENARIOS = tuple(_PLAYER_TRADE_POLICY_SPECS) + tuple(
    _PLAYER_COLONY_BOYCOTT_SPECS
)

# TCountry::SetTradePolicyTo -- vtable index 0x12 -> byte offset 0x48.
_VT_SET_TRADE_POLICY = 0x12 * 4
_GNATION_NEED_LEVELS = 0x14       # TCountry::needLevelByNation[23]
_GNATION_BOYCOTT_FLAGS = 0x918    # colonyBoycottFlags[23]
_FN_SET_TRADE_POLICY_GP = 0x004DD040  # TGreatPower::SetTradePolicyTo
_FN_COLONY_BOYCOTT = 0x004DD0C0  # SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations

_PLAYER_POLICY_ALL_SCENARIOS = (
    _PLAYER_DIPLOMACY_POLICY_SCENARIOS + _PLAYER_TRADE_BOYCOTT_SCENARIOS
)


def _drive_player_diplomacy_policy(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    drive: str,
) -> dict[str, object]:
    if drive in _PLAYER_DIPLO_POLICY_SPECS:
        spec = _PLAYER_DIPLO_POLICY_SPECS[drive]
        target_sel, ops = spec[0], spec[1]
        policy, action, confirm = spec[2], spec[3], spec[4]
        bool_result = spec[5] if len(spec) > 5 else False
        tail = ("policy", policy, action, confirm, bool_result)
    elif drive in _PLAYER_TRADE_POLICY_SPECS:
        target_sel, ops, policy_value = _PLAYER_TRADE_POLICY_SPECS[drive]
        tail = ("trade", policy_value)
    else:
        target_sel, ops = _PLAYER_COLONY_BOYCOTT_SPECS[drive]
        tail = ("colony",)
    sim_mgr = _u32(session, _SIM_MGR)
    diplo = _diplomacy_mgr(session)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    slots = {
        "s": source,
        "t": None,
        "m1": (source + 1) % _MAJOR_NATION_COUNT,
        "m2": (source + 2) % _MAJOR_NATION_COUNT,
        "minor": _MINOR_NATION_FIRST_SLOT,
        "self": source,
    }
    target = slots[target_sel]
    slots["t"] = target
    for op in ops:
        kind = op[0]
        if kind == "mission":
            _dip_set_mission(
                session, diplo, slots[op[1]], slots[op[2]], op[3]
            )
        elif kind == "rel":
            stamp = op[4] if len(op) > 4 else -1
            _dip_set_relation(
                session, diplo, slots[op[1]], slots[op[2]], op[3], stamp
            )
        elif kind == "grant":
            _invoke_thiscall(
                session,
                _FN_SET_DIPLO_GRANT,
                nation,
                records,
                occurrences,
                breakpoint_roles,
                args=(slots[op[1]], op[2]),
            )
        elif kind == "treasury":
            session.assign(
                f"*(int*)0x{nation + 0x10:08x}", op[1]
            )
        elif kind == "budget":
            session.assign(
                f"*(int*)0x{nation + _GNATION_BUDGET_BASE:08x}", op[1]
            )
        elif kind == "grant_total":
            session.assign(
                f"*(int*)0x{nation + _GNATION_GRANT_TOTAL:08x}", op[1]
            )
        elif kind == "policy":
            session.assign(
                f"*(short*)0x{nation + _GNATION_POLICIES + 2 * slots[op[1]]:08x}",
                op[2],
            )
        elif kind == "colony":
            terrain = _u32(
                session, _TERRAIN_TABLE + 4 * slots[op[1]]
            )
            session.assign(
                f"*(short*)0x{terrain + _TERRAIN_ENCODED_SLOT:08x}",
                200 + slots[op[2]],
            )
        elif kind == "need":
            session.assign(
                f"*(short*)0x{nation + _GNATION_NEED_LEVELS + 2 * slots[op[1]]:08x}",
                op[2],
            )
        elif kind == "boycott":
            session.assign(
                f"*(unsigned char*)0x{nation + _GNATION_BOYCOTT_FLAGS + slots[op[1]]:08x}",
                op[2],
            )
        elif kind == "colony_trade":
            colony = _u32(session, _TERRAIN_TABLE + 4 * slots[op[1]])
            _invoke_virtual(
                session,
                colony,
                _VT_SET_TRADE_POLICY,
                records,
                occurrences,
                breakpoint_roles,
                args=(slots[op[2]], op[3]),
            )
        else:
            raise RuntimeError(f"unknown diplomacy setup op {kind!r}")
    if tail[0] == "policy":
        _, policy, action, confirm, bool_result = tail
        toggle = _toggle_player_policy(
            session,
            nation,
            diplo,
            target,
            policy,
            action,
            confirm,
            records,
            occurrences,
            breakpoint_roles,
            bool_result=bool_result,
        )
    elif tail[0] == "trade":
        # TogglePlayerTradePolicyResult: self -> 3, invalid -> -reject mode,
        # else SetTradePolicyTo(target, need == value ? 100 : value) -> 1.
        policy_value = tail[1]
        nation_slot = _s16(session, nation + _GNATION_SLOT)
        if nation_slot == target:
            toggle = 3
        else:
            trade_action = 11 if policy_value == 300 else 9
            valid = _invoke_thiscall(
                session,
                _FN_VALIDATE_DIPLO_ACTION,
                diplo,
                records,
                occurrences,
                breakpoint_roles,
                args=(nation_slot, target, trade_action),
            ) & 0xFF
            if not valid:
                toggle = -_s16(session, diplo + _DIPLO_PROPOSAL_MODE)
            else:
                need = _s16(
                    session, nation + _GNATION_NEED_LEVELS + 2 * target
                )
                _invoke_thiscall(
                    session,
                    _FN_SET_TRADE_POLICY_GP,
                    nation,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(
                        target,
                        100 if need == policy_value else policy_value,
                    ),
                )
                toggle = 1
    else:
        # RunConfiguredPlayerColonyBoycott: decode the target's controlling
        # nation and toggle the boycott flag through the real refresh path.
        colony = _u32(session, _TERRAIN_TABLE + 4 * target)
        encoded = _s16(session, colony + _TERRAIN_ENCODED_SLOT)
        if encoded >= 200:
            controlling = encoded - 200
        elif encoded >= 100:
            controlling = encoded - 100
        else:
            controlling = _s16(session, colony + _GNATION_SLOT)
        if controlling != _s16(session, nation + _GNATION_SLOT):
            flag = _u8(session, nation + _GNATION_BOYCOTT_FLAGS + target)
            _invoke_thiscall(
                session,
                _FN_COLONY_BOYCOTT,
                nation,
                records,
                occurrences,
                breakpoint_roles,
                args=(target, 1 if flag == 0 else 0),
            )
        toggle = 1
    result = _capture_diplomacy_phase(session)
    result["toggle"] = toggle
    return result


# --- nation-economy retail drives ----------------------------------------------
# Mirrors the NativeTradeCases.cpp single-function economy cases. Each spec is a
# list of ordered steps on the active nation; "vt" invokes the production
# virtual through the retail vtable, "vtai" on the first TAutoGreatPower.

_VT_PURCHASE_ITEM = 0x20 * 4              # TCountry::PurchaseItem index 0x20
_VT_RECOMPUTE_AID_BUDGET = 0x59 * 4       # RecomputeDiplomacyAidBudgetScoreFromResourceWeights
_VT_RESET_NEED_SCORES = 0x5A * 4          # ResetDiplomacyNeedScoresAndClearAidAllocationMatrix
_VT_RECALL_TRADE_BIDS = 0x5B * 4          # RecallTradeBids
_VT_ADD_AID_CELL = 0x5D * 4               # AddAmountToAidAllocationMatrixCellAndTotal
_VT_RESET_NEED_SLOTS = 0x61 * 4           # ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches
_VT_SET_ITEM_POTENTIALS = 0x69 * 4        # SetItemPotentials
_VT_REMEMBER_TRADE_BIDS = 0x6A * 4        # RememberTradeBids
_VT_RESET_POLICY_GRANTS = 0x73 * 4        # ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants
_VT_DECREMENT_NEED = 0x79 * 4             # DecrementNeedLevelByNationStep index 121

_GNATION_REMEMBERED_OFFERS = 0x250
_GNATION_ITEM_POTENTIALS = 0x1C6
_GNATION_UNFILLED_OFFERS = 0xB0
_GNATION_AID_MATRIX = 0x280
_GNATION_BUDGET_POOL_BASE = 0x840
_GNATION_BUDGET_POOL_DELTA = 0x844
_CITY_ORDER_COUNTS = 0x5C
_CITY_STOCKS = 0xB6

_RESOURCE_STEEL = 11
_MINOR_SLOT = 7


def _nation_economy_common_seeds() -> list[tuple]:
    """Shared seeding for recall_trade_bids / player_trade_phase_reset."""
    return [
        ("z", _GNATION_REMEMBERED_OFFERS, 46),
        ("fill_short", _GNATION_ITEM_POTENTIALS, 23, 9),
        ("cs", 0, 3),
        ("cs", 1, 4),
        ("cs", 2, 5),
        ("ssi", _GNATION_REMEMBERED_OFFERS, 0, 7),
        ("ssi", _GNATION_REMEMBERED_OFFERS, 1, -1),
        ("ssi", _GNATION_REMEMBERED_OFFERS, 2, 2),
        ("ss", _GNATION_UNFILLED_OFFERS, 4),
        ("si", _GNATION_BUDGET_POOL_BASE, 600),
        ("si", _GNATION_BUDGET_POOL_DELTA, -140),
        ("ss", 0xA4, 19),
        ("ss", 0xA2, 7),
    ]


_NATION_ECONOMY_SPECS = {
    "trade_policy_set": [
        ("call", _FN_SET_DIPLO_GRANT, ("m1", 1000)),
        ("vt", _VT_SET_TRADE_POLICY, ("m1", 300)),
    ],
    "trade_policy_step": [
        ("ssi", _GNATION_NEED_LEVELS, "t0", 75),
        ("si", 0x10, 10001),
        ("vt", _VT_DECREMENT_NEED, ("t0",)),
    ],
    "recall_trade_bids": [
        ("z", _GNATION_AID_MATRIX, 0x170 * 4),
        ("sii", _GNATION_AID_MATRIX, 0, 17),
        ("sii", _GNATION_AID_MATRIX, 0x16F, -9),
        ("vt", _VT_RECALL_TRADE_BIDS, ()),
    ],
    "player_trade_phase_reset": [
        ("co", {1: 2, 5: 1, 10: 1}),
        ("vt", _VT_ADD_AID_CELL, (37, _RESOURCE_STEEL, _MINOR_SLOT)),
        ("vt", _VT_RESET_NEED_SCORES, ()),
    ],
    "ai_capital_selection_trade_bids": [
        ("vtai", _VT_RESET_NEED_SLOTS, ()),
    ],
    "trade_capacity_refresh": [
        ("co", {1: 2, 5: 1, 10: 1}),
        ("vt", _VT_RECOMPUTE_AID_BUDGET, ()),
    ],
    "major_trade_settlement": [
        ("vt", _VT_PURCHASE_ITEM, (8, 3, 7)),
        ("vt", _VT_PURCHASE_ITEM, (13, -2, 5)),
        ("vt", _VT_PURCHASE_ITEM, (8, -1, 4)),
    ],
    "purchased_items_phase": [
        ("vt", _VT_SET_ITEM_POTENTIALS, (8, -1)),
        ("vt", _VT_SET_ITEM_POTENTIALS, (13, -1)),
        ("vt", _VT_REMEMBER_TRADE_BIDS, ()),
        ("vt", _VT_PURCHASE_ITEM, (8, 3, 7)),
        ("vt", _VT_PURCHASE_ITEM, (7, -30, 1)),
        ("vt", _VT_ADD_PURCHASED_ITEMS, ()),
    ],
    "direct_transport": [
        ("z", 0x10E, 46),
        ("z", 0x13C, 46),
        ("ssi", 0x10E, 0, 7),
        ("ssi", 0x13C, 0, 7),
        ("ssi", 0x10E, _RESOURCE_STEEL, 10),
        ("ssi", 0x13C, _RESOURCE_STEEL, 4),
        ("ss", 0xA6, 15),
        ("ss", 0xA8, 11),
        ("cs", _RESOURCE_STEEL, 2),
        ("cvt_result", 0x13 * 4, (_RESOURCE_STEEL, 9), "short"),
    ],
    "transport_need_allocation": [
        ("vtm", 0x14 * 4, ()),
    ],
    "transported_items_phase": [
        ("z", 0x222, 46),
        ("cs", 0, 3),
        ("cs", 1, 2),
        ("cs", 22, 11),
        ("ssi", 0x222, 0, 5),
        ("ssi", 0x222, 1, -7),
        ("ssi", 0x222, 22, 4),
        ("vt", 0x41 * 4, ()),
    ],
    "rolling_stock": [
        ("cs", 9, 1),
        ("cs", _RESOURCE_STEEL, 1),
        ("ss", 0xA6, 15),
        ("vt_result", 0x4A * 4, (), "char"),
    ],
    "rolling_stock_insufficient_resources": [
        ("cs", 9, 0),
        ("cs", _RESOURCE_STEEL, 1),
        ("ss", 0xA6, 15),
        ("vt_result", 0x4A * 4, (), "char"),
    ],
    "merchant_marine": [
        ("cs", 9, 3),
        ("cs", 8, 1),
        ("ss", 0xA4, 15),
        ("vt_result", 0x4B * 4, (), "char"),
    ],
    "created_items_phase": [
        ("vt", 0x43 * 4, ()),
    ],
    "aid_allocation": [
        ("vt", _VT_ADD_AID_CELL, (37, _RESOURCE_STEEL, _MINOR_SLOT)),
    ],
    "power_plant_upgrade": [
        ("cb", 0x04, 0),
        ("si", 0x10, 10000),
        ("cvt", 0x18 * 4, (1,)),
    ],
}

_NATION_ECONOMY_SPECS["recall_trade_bids"] = (
    _nation_economy_common_seeds() + _NATION_ECONOMY_SPECS["recall_trade_bids"]
)
_NATION_ECONOMY_SPECS["player_trade_phase_reset"] = (
    _nation_economy_common_seeds() + _NATION_ECONOMY_SPECS["player_trade_phase_reset"]
)


def _drive_nation_economy(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    drive: str,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    city = _u32(session, nation + 0x894)
    slots = {
        "s": source,
        "m1": (source + 1) % _MAJOR_NATION_COUNT,
        "t0": 0 if source != 0 else 1,
        "minor": _MINOR_NATION_FIRST_SLOT,
    }

    def _slot(value):
        return slots[value] if isinstance(value, str) else value

    def _mask_result(value: int, mode: str) -> int:
        if mode == "char":
            return 1 if (value & 0xFF) != 0 else 0
        if mode == "short":
            value &= 0xFFFF
            return value - 0x10000 if value & 0x8000 else value
        return value

    toggle = 0
    for step in _NATION_ECONOMY_SPECS[drive]:
        kind = step[0]
        if kind == "vt":
            _invoke_virtual(
                session,
                nation,
                step[1],
                records,
                occurrences,
                breakpoint_roles,
                args=tuple(_slot(a) for a in step[2]),
            )
        elif kind == "vtai":
            target_nation = 0
            for slot in range(_MAJOR_NATION_COUNT):
                candidate = _nation_pointer(session, slot)
                if candidate == 0:
                    continue
                if (
                    _runtime_class(
                        session, candidate, records, occurrences, breakpoint_roles
                    )
                    == _CLASS_AUTO_GREAT_POWER
                ):
                    target_nation = candidate
                    break
            if target_nation == 0:
                raise RuntimeError("retail fixture has no AutoGreatPower")
            _invoke_virtual(
                session,
                target_nation,
                step[1],
                records,
                occurrences,
                breakpoint_roles,
                args=tuple(_slot(a) for a in step[2]),
            )
        elif kind == "call":
            _invoke_thiscall(
                session,
                step[1],
                nation,
                records,
                occurrences,
                breakpoint_roles,
                args=tuple(_slot(a) for a in step[2]),
            )
        elif kind == "vt_result":
            toggle = _mask_result(
                _invoke_virtual(
                    session,
                    nation,
                    step[1],
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=tuple(_slot(a) for a in step[2]),
                ),
                step[3],
            )
        elif kind in ("cvt", "cvt_result"):
            if city == 0:
                raise RuntimeError("retail nation has no city")
            value = _invoke_virtual(
                session,
                city,
                step[1],
                records,
                occurrences,
                breakpoint_roles,
                args=tuple(_slot(a) for a in step[2]),
            )
            if kind == "cvt_result":
                toggle = _mask_result(value, step[3])
        elif kind == "vtm":
            minister = _u32(session, nation + 0x98)
            if minister == 0:
                raise RuntimeError("retail nation has no interior minister")
            _invoke_virtual(
                session,
                minister,
                step[1],
                records,
                occurrences,
                breakpoint_roles,
                args=tuple(_slot(a) for a in step[2]),
            )
        elif kind == "cb":
            if city == 0:
                raise RuntimeError("retail nation has no city")
            session.assign(
                f"*(unsigned char*)0x{city + step[1]:08x}", step[2]
            )
        elif kind == "ss":
            session.assign(f"*(short*)0x{nation + step[1]:08x}", step[2])
        elif kind == "ssi":
            session.assign(
                f"*(short*)0x{nation + step[1] + 2 * _slot(step[2]):08x}",
                step[3],
            )
        elif kind == "si":
            session.assign(f"*(int*)0x{nation + step[1]:08x}", step[2])
        elif kind == "sii":
            session.assign(
                f"*(int*)0x{nation + step[1] + 4 * _slot(step[2]):08x}",
                step[3],
            )
        elif kind == "z":
            session.write_memory(nation + step[1], b"\x00" * step[2])
        elif kind == "fill_short":
            session.write_memory(
                nation + step[1],
                struct.pack("<h", step[3]) * step[2],
            )
        elif kind == "co":
            if city == 0:
                raise RuntimeError("retail nation has no city")
            session.write_memory(city + _CITY_ORDER_COUNTS, b"\x00" * 28)
            for index, value in step[1].items():
                session.assign(
                    f"*(short*)0x{city + _CITY_ORDER_COUNTS + 2 * index:08x}",
                    value,
                )
        elif kind == "cs":
            if city == 0:
                raise RuntimeError("retail nation has no city")
            session.assign(
                f"*(short*)0x{city + _CITY_STOCKS + 2 * step[1]:08x}", step[2]
            )
        else:
            raise RuntimeError(f"unknown economy step {kind!r}")
    result = _capture_trade_phase(session)
    result["toggle"] = toggle
    return result


def _drive_trade_market_price(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunTradeMarketPrice: seed the 17 priced category rows, then call
    TTradeMgr::CalculateNewWorldPrices."""
    trade_mgr = _u32(session, _TRADE_MGR)
    overrides = {
        0: (1000, 100, 1, 4.5),
        1: (50, 10, 20, 10.0),
        2: (50, 1000, 0, 100.0),
        3: (400, 100, 10, 10.0),
        4: (800, 100, 10, 10.0),
        5: (720, 100, 14, 10.5),
        6: (20000, 200, 10, 10.0),
        7: (500, 50, 3, 11.0),
        13: (1700, 800, 19, 10.25),
        14: (1850, 900, 5, 8.5),
        15: (900, 600, 100, 0.0),
        16: (2222, 1000, 77, 3.25),
    }
    for resource in range(17):
        row = trade_mgr + _TRADE_ROW_BASE + resource * _TRADE_ROW_STRIDE
        price, base_price, requests, adjusted = overrides.get(
            resource,
            (400 + resource * 17, 200 + resource * 13, 20 + resource,
             resource + 0.5),
        )
        session.assign(f"*(short*)0x{row + 4:08x}", 100 + resource)
        session.assign(f"*(short*)0x{row + 6:08x}", price)
        session.assign(f"*(short*)0x{row + 0x16:08x}", base_price)
        session.assign(f"*(short*)0x{row + 8:08x}", requests)
        session.assign(f"*(short*)0x{row + 0xA:08x}", 40 + resource)
        session.assign(f"*(short*)0x{row + 0x14:08x}", 60 + resource)
        session.write_memory(row + 0xC, struct.pack("<d", adjusted))
    _invoke_thiscall(
        session,
        _CALCULATE_NEW_WORLD_PRICES,
        trade_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    result = _capture_trade_phase(session)
    result["toggle"] = 0
    return result


def _drive_diplomacy_economy(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    drive: str,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    toggle = 0
    if drive == "diplomacy_grant_entry_updates_treasury":
        toggle = (
            _invoke_thiscall(
                session,
                _FN_SET_DIPLO_GRANT,
                nation,
                records,
                occurrences,
                breakpoint_roles,
                args=(0, 10000),
            )
            & 0xFF
        )
    else:
        # diplomacy_reset_preserves_recurring_grants
        for target in range(_NATION_SLOT_COUNT):
            _invoke_thiscall(
                session,
                _FN_SET_DIPLO_GRANT,
                nation,
                records,
                occurrences,
                breakpoint_roles,
                args=(target, -1),
            )
        m1 = (source + 1) % _MAJOR_NATION_COUNT
        session.assign(
            f"*(short*)0x{nation + _GNATION_POLICIES + 2 * m1:08x}", 0x133
        )
        for target, amount in (
            ((source + 2) % _MAJOR_NATION_COUNT, 1000),
            ((source + 3) % _MAJOR_NATION_COUNT, 3000 | 0x4000),
        ):
            _invoke_thiscall(
                session,
                _FN_SET_DIPLO_GRANT,
                nation,
                records,
                occurrences,
                breakpoint_roles,
                args=(target, amount),
            )
        _invoke_virtual(
            session,
            nation,
            _VT_RESET_POLICY_GRANTS,
            records,
            occurrences,
            breakpoint_roles,
        )
    result = _capture_diplomacy_phase(session)
    result["toggle"] = toggle
    return result


# --- military_maintenance / turn-tail gate retail drives -----------------------

_FN_PAY_FOR_MILITARY = 0x004E3560
_FN_UNIT_DETACH_ORDER = 0x005C31C0
_FN_MILITARY_UNIT_CTOR = 0x005C2DF0
_FN_MILITARY_UNIT_INIT = 0x005C2F50
_TMILITARY_UNIT_SIZE = 0x44
_VT_LIST_GET_COUNT = 0x12 * 4
_VT_LIST_GET_BY_ORDINAL = 0x13 * 4
_VT_UNIT_FREE = 0x07 * 4
_FN_IS_ELIGIBLE_FOR_EVENTS = 0x00581280
_FN_GET_BYTE_FLAG_8 = 0x004A6DD0
_FN_GET_ECONOMIC_TURN = 0x0057D8B0
_VT_INIT_DIPLOMACY_NOTICES = 0x7F * 4
_VT_DISPATCH_MISSION_CALLBACKS = 0x30 * 4


def _new_military_unit(
    session: GdbSession,
    kind: int,
    node_context: int,
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
        args=(_TMILITARY_UNIT_SIZE,),
    )
    _invoke_thiscall(
        session,
        _FN_MILITARY_UNIT_CTOR,
        unit,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _FN_MILITARY_UNIT_INIT,
        unit,
        records,
        occurrences,
        breakpoint_roles,
        args=(kind, node_context, nation_slot),
    )
    return unit


def _drive_military_maintenance(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunMilitaryMaintenance: drain the nation's unit list, create
    minutemen/artillery/armor plus three owned and one foreign ship, then run
    TGreatPower::PayForMilitary against a seeded treasury."""
    sim_mgr = _u32(session, _SIM_MGR)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    foreign = 0 if source != 0 else 1
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    unit_list = _u32(session, nation + 0x44)
    while (
        _invoke_virtual(
            session, unit_list, _VT_LIST_GET_COUNT, records, occurrences,
            breakpoint_roles,
        )
        != 0
    ):
        unit = _invoke_virtual(
            session,
            unit_list,
            _VT_LIST_GET_BY_ORDINAL,
            records,
            occurrences,
            breakpoint_roles,
            args=(1,),
        )
        _invoke_thiscall(
            session,
            _FN_UNIT_DETACH_ORDER,
            unit,
            records,
            occurrences,
            breakpoint_roles,
        )
        _invoke_virtual(
            session, unit, _VT_UNIT_FREE, records, occurrences,
            breakpoint_roles,
        )
    _new_military_unit(
        session, 0, -1, source, records, occurrences, breakpoint_roles
    )
    _new_military_unit(
        session, 6, -1, source, records, occurrences, breakpoint_roles
    )
    _new_military_unit(
        session, 21, -1, source, records, occurrences, breakpoint_roles
    )
    _new_military_unit(
        session, 21, -1, foreign, records, occurrences, breakpoint_roles
    )
    zone_head = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
    _new_ship(
        session, 3, zone_head, source, "maintenance-owned-slot3",
        records, occurrences, breakpoint_roles,
    )
    _new_ship(
        session, 9, zone_head, source, "maintenance-owned-slot9",
        records, occurrences, breakpoint_roles,
    )
    _new_ship(
        session, 12, zone_head, source, "maintenance-owned-slot12",
        records, occurrences, breakpoint_roles,
    )
    _new_ship(
        session, 12, zone_head, foreign, "maintenance-foreign-slot12",
        records, occurrences, breakpoint_roles,
    )
    session.assign(f"*(int*)0x{nation + 0x10:08x}", 10000)
    session.assign(f"*(int*)0x{nation + 0x960:08x}", 0)
    _invoke_thiscall(
        session,
        _FN_PAY_FOR_MILITARY,
        nation,
        records,
        occurrences,
        breakpoint_roles,
    )
    result = _capture_trade_phase(session)
    result["toggle"] = 0
    return result


def _drive_diplomacy_offer_gate(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunDiplomacyOfferGate: the map-action manager flag byte ANDed
    with the active nation's event-processing eligibility."""
    sim_mgr = _u32(session, _SIM_MGR)
    action_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    source = _s16(session, sim_mgr + 0x2E)
    flag = _invoke_thiscall(
        session,
        _FN_GET_BYTE_FLAG_8,
        action_mgr,
        records,
        occurrences,
        breakpoint_roles,
    ) & 0xFF
    eligible = _invoke_thiscall(
        session,
        _FN_IS_ELIGIBLE_FOR_EVENTS,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
        args=(source,),
    ) & 0xFF
    result = _capture_trade_phase(session)
    result["toggle"] = 1 if (flag != 0 and eligible != 0) else 0
    return result


def _drive_quarter_gate(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunQuarterGateOffDecade: seed turn 1, recompute the turn-tail
    state code, then evaluate the decade-cinematic gate."""
    sim_mgr = _u32(session, _SIM_MGR)
    diplo = _u32(session, _DIPLOMACY_MGR)
    source = _s16(session, sim_mgr + 0x2E)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 1)
    session.assign(f"*(signed char*)0x{diplo + 0x78E:08x}", source)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x10)
    last_processed = _s8(session, diplo + 0x78E)
    if last_processed != -1:
        active = _s16(session, sim_mgr + 0x2E)
        session.assign(
            f"*(int*)0x{sim_mgr + 0x04:08x}",
            (1 if last_processed != active else 0) + 0x16,
        )
    tick = _invoke_thiscall(
        session,
        _FN_GET_ECONOMIC_TURN,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    ) & 0xFFFF
    if tick & 0x8000:
        tick -= 0x10000
    decade_flag = _u8(session, sim_mgr + 0x6E + tick // 0x28)
    decade_cinematic = (tick % 0x28) == 0 and decade_flag != 0
    result = _capture_trade_phase(session)
    result["toggle"] = 1 if decade_cinematic else 0
    return result


def _drive_return_to_map(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunReturnToMapClearsNoticeQueues: state 0x12 -> 5, then for each
    eligible major nation run InitializeDiplomacyNotices +
    DispatchMissionNodeCallbacksAndClearQueue."""
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x12)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 5)
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        if (
            _invoke_thiscall(
                session,
                _FN_IS_ELIGIBLE_FOR_EVENTS,
                sim_mgr,
                records,
                occurrences,
                breakpoint_roles,
                args=(slot,),
            )
            & 0xFF
            == 0
        ):
            continue
        _invoke_virtual(
            session, nation, _VT_INIT_DIPLOMACY_NOTICES, records,
            occurrences, breakpoint_roles,
        )
        _invoke_virtual(
            session, nation, _VT_DISPATCH_MISSION_CALLBACKS, records,
            occurrences, breakpoint_roles,
        )
    result = _capture_diplomacy_phase(session)
    result["toggle"] = 0
    return result


def _invoke_production_turn_state(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    turn_state: int,
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", turn_state)
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
        _ADVANCE_TURN_STATE,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _drive_turn_state_diplomacy(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    turn_state: int,
) -> dict[str, object]:
    if turn_state == 0xD:
        action_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
        session.assign(f"*(unsigned char*)0x{action_mgr + 0x08:08x}", 0)
    _invoke_production_turn_state(
        session, records, occurrences, breakpoint_roles, turn_state
    )
    result = _capture_diplomacy_phase(session)
    result.update(
        _capture_missions(
            session, records, occurrences, breakpoint_roles
        )
    )
    result["toggle"] = 0
    result["dispatched_event"] = _current_turn_event(session)
    result["rng"] = _capture_rng_state(
        session, records, occurrences, breakpoint_roles
    )
    return result


def _drive_turn_state_quarter_gate(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    diplomacy_mgr = _u32(session, _DIPLOMACY_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 1)
    session.assign(
        f"*(short*)0x{diplomacy_mgr + 0x78E:08x}",
        _s16(session, sim_mgr + 0x2E),
    )
    _invoke_production_turn_state(
        session, records, occurrences, breakpoint_roles, 0x0E
    )
    result = _capture_trade_phase(session)
    result["toggle"] = 0
    result["dispatched_event"] = _current_turn_event(session)
    result["rng"] = _capture_rng_state(
        session, records, occurrences, breakpoint_roles
    )
    return result


def _drive_turn_state_combat_moves(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    _invoke_production_turn_state(
        session, records, occurrences, breakpoint_roles, 0x14
    )
    result = _capture_military_phase(session)
    result["dispatched_event"] = _current_turn_event(session)
    result["rng"] = _capture_rng_state(
        session, records, occurrences, breakpoint_roles
    )
    return result


def _drive_turn_state_military_cleanup(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    perturb_ai: bool = False,
    perturb_damaged_mission: bool = False,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 2)
    if perturb_ai:
        _configure_ai_naval_development_pressure(
            session, records, occurrences, breakpoint_roles
        )
    if perturb_damaged_mission:
        _configure_reassess_missions_damaged(
            session, records, occurrences, breakpoint_roles
        )
    _invoke_production_turn_state(
        session, records, occurrences, breakpoint_roles, 0x15
    )
    result = _capture_military_cleanup(
        session, records, occurrences, breakpoint_roles
    )
    result.update(_capture_trade_phase(session))
    result.update(_capture_diplomacy_phase(session))
    result.update(
        _capture_ai_development(
            session, records, occurrences, breakpoint_roles
        )
    )
    result["toggle"] = 0
    result["dispatched_event"] = _current_turn_event(session)
    result["rng"] = _capture_rng_state(
        session, records, occurrences, breakpoint_roles
    )
    return result


# --- province ownership retail drives ------------------------------------------
# Mirror RunProvinceLossWithStationedUnit / RunProvinceOwnerOceanContext: both
# pick the active nation's first non-capital owned province with linked tiles,
# then call the real TMapMgr::ChangeProvinceOwner.

_FN_CHANGE_PROVINCE_OWNER = 0x00513290
_FN_CIV_UNIT_CTOR = 0x005C28C0
_FN_CIV_UNIT_INIT = 0x005C2940
_TCIV_UNIT_SIZE = 0x28
_TERRAIN_DESCRIPTOR_TABLE = 0x006A4310
_FN_STRETCH_PROVINCE_ADD = 0x0055E9C0
_VT_MISSION_MATCHES = 0x13 * 4
_VT_MISSION_HOLD = 0x25 * 4


def _find_non_capital_owned_province(session: GdbSession, nation: int) -> int:
    """First ownedRegionList entry whose city tile differs from homeTileIndex
    and whose linkedRegionCount is nonzero (-1 when none)."""
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    city_score_table = _u32(session, map_state + 0x10)
    owned_regions = _u32(session, nation + 0x90)
    home_tile = _s16(session, nation + 0x88)
    if owned_regions == 0:
        return -1
    for region_id in _longint_list_entries(session, owned_regions):
        province = city_score_table + region_id * _PROVINCE_STRIDE
        if (
            _s16(session, province + 0x04) != home_tile
            and _s8(session, province + 0x3A) > 0
        ):
            return region_id
    return -1


def _drive_province_loss(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    province_id = _find_non_capital_owned_province(session, nation)
    if province_id < 0:
        raise RuntimeError(
            "retail fixture has no non-capital owned province with linked tiles"
        )
    minor_slot = -1
    for slot in range(7, 23):
        if _u32(session, _TERRAIN_DESCRIPTOR_TABLE + slot * 4) != 0:
            minor_slot = slot
            break
    if minor_slot < 0:
        raise RuntimeError("retail fixture has no minor nation")
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    record = _u32(session, map_state + 0x10) + province_id * _PROVINCE_STRIDE
    tile = _s16(session, record + 0x42)
    civilian = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_TCIV_UNIT_SIZE,),
    )
    _invoke_thiscall(
        session, _FN_CIV_UNIT_CTOR, civilian, records, occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _FN_CIV_UNIT_INIT,
        civilian,
        records,
        occurrences,
        breakpoint_roles,
        args=(0, tile, source),
    )
    _new_military_unit(
        session, 0, province_id, source, records, occurrences,
        breakpoint_roles,
    )
    _new_military_unit(
        session, 0, -1, source, records, occurrences, breakpoint_roles
    )
    _invoke_thiscall(
        session,
        _FN_CHANGE_PROVINCE_OWNER,
        map_state,
        records,
        occurrences,
        breakpoint_roles,
        args=(province_id, minor_slot),
    )
    result = _capture_military_phase(session)
    result["civilians"] = _capture_civilians_phase(session)["civilians"]
    return result


def _drive_province_ocean(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    province_id = _find_non_capital_owned_province(session, nation)
    if province_id < 0:
        raise RuntimeError(
            "retail fixture has no non-capital owned province with linked tiles"
        )
    ai_slot = -1
    for slot in range(_MAJOR_NATION_COUNT):
        if slot != source and _nation_pointer(session, slot) != 0:
            ai_slot = slot
            break
    if ai_slot < 0:
        raise RuntimeError("retail fixture has no AI great power")
    zone = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
    if zone == 0:
        raise RuntimeError("retail fixture has no ocean zone context")
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    record = _u32(session, map_state + 0x10) + province_id * _PROVINCE_STRIDE
    session.assign(f"*(signed char*)0x{record + 0x08:08x}", 0)
    _invoke_thiscall(
        session,
        _FN_STRETCH_PROVINCE_ADD,
        zone + 0x34,
        records,
        occurrences,
        breakpoint_roles,
        args=(record,),
    )
    ai = _nation_pointer(session, ai_slot)
    saved_eligibility = _u8(session, ai + 0xA0)
    session.assign(f"*(unsigned char*)0x{ai + 0xA0:08x}", 0)
    _invoke_thiscall(
        session,
        _FN_CHANGE_PROVINCE_OWNER,
        map_state,
        records,
        occurrences,
        breakpoint_roles,
        args=(province_id, ai_slot),
    )
    session.assign(
        f"*(unsigned char*)0x{ai + 0xA0:08x}", saved_eligibility
    )
    queue = _u32(session, ai + _NATION_MISSION_QUEUE)
    held = False
    for mission in _sorted_ptr_list_entries(session, queue):
        if (
            _invoke_virtual(
                session,
                mission,
                _VT_MISSION_MATCHES,
                records,
                occurrences,
                breakpoint_roles,
                args=(3, province_id, 0),
            )
            & 0xFF
            != 0
        ):
            _invoke_virtual(
                session,
                mission,
                _VT_MISSION_HOLD,
                records,
                occurrences,
                breakpoint_roles,
                args=(0,),
            )
            held = True
            break
    if not held:
        raise RuntimeError(
            "retail province ownership change created no defend mission"
        )
    result = _capture_missions(
        session, records, occurrences, breakpoint_roles
    )
    result["military"] = {
        "province_owners": _capture_military_phase(session)["military"][
            "province_owners"
        ]
    }
    return result


# --- civilian construction/development retail drives ---------------------------
# Mirror RunCompletedRailSection / RunIssuedRailSection /
# RunCompletedResourceDevelopment: engineer and worker TCivUnits driven through
# the real SetOrders/MoveTo/ContinueOrders virtuals.

_FN_APPLY_RAIL_FLAGS = 0x00513FF0
_FN_SET_CIV_DEV_NIBBLE = 0x005136A0
_ENGINEER_RAIL_COST_TABLE = 0x006531D8
_VT_CIV_MOVE_TO = 0x0A * 4
_VT_CIV_CONTINUE_ORDERS = 0x0B * 4
_VT_CIV_SET_ORDERS = 0x0D * 4
_UNIT_ORDER_LAY_RAIL = 5
_UNIT_ORDER_DEVELOP_RESOURCE = 10
_CIV_UNIT_ENGINEER = 4
_RAIL_ALLOWED_TERRAIN = (0, 1, 6, 7)


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
        args=(_TCIV_UNIT_SIZE,),
    )
    _invoke_thiscall(
        session, _FN_CIV_UNIT_CTOR, unit, records, occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _FN_CIV_UNIT_INIT,
        unit,
        records,
        occurrences,
        breakpoint_roles,
        args=(kind, tile, nation_slot),
    )
    return unit


def _hex_deltas(session: GdbSession) -> tuple[list[int], list[int]]:
    col_deltas = list(
        struct.unpack(
            "<6h", session.read_memory(_HEX_COL_DELTAS, 12)
        )
    )
    row_deltas = list(
        struct.unpack(
            "<6h", session.read_memory(_HEX_ROW_DELTAS, 12)
        )
    )
    return col_deltas, row_deltas


def _tile_record(session: GdbSession, terrain_base: int, tile: int) -> dict:
    raw = session.read_memory(
        terrain_base + tile * _TERRAIN_RECORD_STRIDE, _TERRAIN_RECORD_STRIDE
    )
    return {
        "tile": tile,
        "owner": struct.unpack("<b", raw[0x04:0x05])[0],
        "adjacency": struct.unpack("<b", raw[0x06:0x07])[0],
        "dev_nibbles": raw[0x0C],
        "pending": raw[0x0D],
        "rail_flags": raw[0x17],
        "active_flags": struct.unpack("<H", raw[0x1C:0x1E])[0],
        "province": struct.unpack("<h", raw[0x14:0x16])[0],
    }


def _find_issuable_rail_section(
    snapshot: _TerrainSnapshot,
    nation_slot: int,
    col_deltas: list[int],
    row_deltas: list[int],
) -> tuple[int, int]:
    """Mirror FindIssuableRailSection: owned, unoccupied, flag-free,
    rail-legal terrain pair in the east direction, columns 2..0x69."""
    for candidate in range(_TILE_COUNT):
        column = candidate % 0x6C
        if column < 2 or column > 0x69:
            continue
        if (
            snapshot.tile_field(candidate, 0x04, "<b") != nation_slot
            or snapshot.has_civilian(candidate)
            or snapshot.tile_field(candidate, 0x06, "<b") != 0
            or snapshot.tile_field(candidate, 0x17, "<B") != 0
            or snapshot.tile_field(candidate, 0x00, "<b")
            not in _RAIL_ALLOWED_TERRAIN
        ):
            continue
        neighbor = _neighbor_tile(
            candidate, _HEX_DIRECTION_EAST, col_deltas, row_deltas
        )
        if neighbor == -1 or neighbor == candidate:
            continue
        if (
            snapshot.tile_field(neighbor, 0x04, "<b") == nation_slot
            and not snapshot.has_civilian(neighbor)
            and snapshot.tile_field(neighbor, 0x06, "<b") == 0
            and snapshot.tile_field(neighbor, 0x17, "<B") == 0
            and snapshot.tile_field(neighbor, 0x00, "<b")
            in _RAIL_ALLOWED_TERRAIN
        ):
            return candidate, neighbor
    return -1, -1


def _terrain_base(session: GdbSession) -> int:
    return _u32(session, _u32(session, _GLOBAL_MAP_STATE) + 0x0C)


def _drive_completed_rail_section(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    source = _s16(session, sim_mgr + 0x2E)
    snapshot = _TerrainSnapshot(session, map_state)
    snapshot.refresh_tiles()
    col_deltas, row_deltas = _hex_deltas(session)
    source_tile, destination_tile = _find_unoccupied_rail_section(
        snapshot, col_deltas, row_deltas
    )
    if source_tile < 0:
        raise RuntimeError("retail map has no clear rail section")
    civilian = _new_civilian_unit(
        session,
        _CIV_UNIT_ENGINEER,
        source_tile,
        source,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _FN_APPLY_RAIL_FLAGS,
        map_state,
        records,
        occurrences,
        breakpoint_roles,
        args=(source_tile, destination_tile, source),
    )
    _invoke_virtual(
        session,
        civilian,
        _VT_CIV_SET_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
        args=(_UNIT_ORDER_LAY_RAIL, source_tile),
    )
    _invoke_virtual(
        session,
        civilian,
        _VT_CIV_MOVE_TO,
        records,
        occurrences,
        breakpoint_roles,
        args=(destination_tile,),
    )
    session.assign(f"*(short*)0x{civilian + 0x24:08x}", 1)
    _invoke_virtual(
        session,
        civilian,
        _VT_CIV_CONTINUE_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
    )
    result = _capture_civilians_phase(session)
    terrain_base = _terrain_base(session)
    result["tiles"] = [
        _tile_record(session, terrain_base, tile)
        for tile in (source_tile, destination_tile)
    ]
    return result


def _drive_issued_rail_section(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    source = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, source)
    snapshot = _TerrainSnapshot(session, map_state)
    snapshot.refresh_tiles()
    col_deltas, row_deltas = _hex_deltas(session)
    source_tile, destination_tile = _find_issuable_rail_section(
        snapshot, source, col_deltas, row_deltas
    )
    if source_tile < 0:
        raise RuntimeError("retail map has no issuable rail section")
    civilian = _new_civilian_unit(
        session,
        _CIV_UNIT_ENGINEER,
        source_tile,
        source,
        records,
        occurrences,
        breakpoint_roles,
    )
    treasury = _eval_int(session, f"*(int*)0x{nation + 0x10:08x}")
    budget_base = _eval_int(session, f"*(int*)0x{nation + 0x8F0:08x}")
    available = treasury + budget_base // 100
    if available < 0:
        available = 0
    if available < 400:
        session.assign(f"*(int*)0x{nation + 0x10:08x}", 10000)
    terrain_kind = _s8(
        session, _terrain_base(session) + destination_tile * 0x24
    )
    cost = _eval_int(
        session,
        f"*(int*)0x{_ENGINEER_RAIL_COST_TABLE + terrain_kind * 4:08x}",
    )
    _invoke_thiscall(
        session,
        _FN_APPLY_RAIL_FLAGS,
        map_state,
        records,
        occurrences,
        breakpoint_roles,
        args=(source_tile, destination_tile, source),
    )
    _invoke_virtual(
        session,
        civilian,
        _VT_CIV_SET_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
        args=(_UNIT_ORDER_LAY_RAIL, source_tile),
    )
    _invoke_virtual(
        session,
        civilian,
        _VT_CIV_MOVE_TO,
        records,
        occurrences,
        breakpoint_roles,
        args=(destination_tile,),
    )
    session.assign(
        f"*(int*)0x{nation + 0x10:08x}",
        _eval_int(session, f"*(int*)0x{nation + 0x10:08x}") - cost,
    )
    result = _capture_civilians_phase(session)
    terrain_base = _terrain_base(session)
    result["tiles"] = [
        _tile_record(session, terrain_base, tile)
        for tile in (source_tile, destination_tile)
    ]
    return result


def _drive_completed_resource_development(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    source = _s16(session, sim_mgr + 0x2E)
    snapshot = _TerrainSnapshot(session, map_state)
    snapshot.refresh_tiles()
    extractive_tile = _find_unoccupied_tile(snapshot)
    if extractive_tile < 0:
        raise RuntimeError("retail map has no unoccupied tile")
    for select_high, value in ((0, 2), (1, 0)):
        _invoke_thiscall(
            session,
            _FN_SET_CIV_DEV_NIBBLE,
            map_state,
            records,
            occurrences,
            breakpoint_roles,
            args=(extractive_tile, select_high, value, 0),
        )
    session.assign(
        f"*(unsigned char*)0x{_terrain_base(session) + extractive_tile * 0x24 + 0x0D:08x}",
        0,
    )
    extractive = _new_civilian_unit(
        session, 0, extractive_tile, source, records, occurrences,
        breakpoint_roles,
    )
    _invoke_virtual(
        session,
        extractive,
        _VT_CIV_SET_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
        args=(_UNIT_ORDER_DEVELOP_RESOURCE, extractive_tile),
    )
    session.assign(f"*(short*)0x{extractive + 0x24:08x}", 1)
    snapshot.refresh_tiles()
    surface_tile = _find_unoccupied_tile(snapshot)
    if surface_tile < 0:
        raise RuntimeError("retail map has only one unoccupied tile")
    for select_high, value in ((0, 2), (1, 0)):
        _invoke_thiscall(
            session,
            _FN_SET_CIV_DEV_NIBBLE,
            map_state,
            records,
            occurrences,
            breakpoint_roles,
            args=(surface_tile, select_high, value, 0),
        )
    session.assign(
        f"*(unsigned char*)0x{_terrain_base(session) + surface_tile * 0x24 + 0x0D:08x}",
        8,
    )
    surface = _new_civilian_unit(
        session,
        _CIV_UNIT_ENGINEER,
        surface_tile,
        source,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_virtual(
        session,
        surface,
        _VT_CIV_SET_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
        args=(_UNIT_ORDER_DEVELOP_RESOURCE, surface_tile),
    )
    session.assign(f"*(short*)0x{surface + 0x24:08x}", 1)
    _invoke_virtual(
        session,
        extractive,
        _VT_CIV_CONTINUE_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_virtual(
        session,
        surface,
        _VT_CIV_CONTINUE_ORDERS,
        records,
        occurrences,
        breakpoint_roles,
    )
    result = _capture_civilians_phase(session)
    terrain_base = _terrain_base(session)
    result["tiles"] = [
        _tile_record(session, terrain_base, tile)
        for tile in (extractive_tile, surface_tile)
    ]
    return result


# --- nation yield-rebuild retail drives ----------------------------------------
# Mirror RunNationResourceYieldRebuild* and RunOwnedRegionDevelopment: the real
# RebuildNationResourceYieldCountersAndDevelopmentTargets /
# AdvanceOwnedRegionDevelopmentCountersAndHandleEvents virtuals.

_VT_REBUILD_YIELD = 0x4D * 4
_VT_ADVANCE_REGION_DEV = 0x4E * 4
_VT_TRANSPORT_INFLUENCE = 0x34 * 4
_VT_LIST_ADD_TAIL = 0x0C * 4
_FN_TTOWN_CTOR = 0x005B6C60
_FN_TTOWN_ITOWN = 0x005B6CD0
_TTOWN_SIZE = 0x50
_RESOURCE_FISH = 19
_RESOURCE_COTTON = 0


def _neighbor_tile_array(tile: int, wrap: int) -> list[int]:
    """Mirror TMapMgr::GetNeighborTileIDArray (0x512b50): fixed per-parity
    offsets; wrap==0 wraps columns at the east/west edges, wrap!=0 returns
    -1 there. Order: NE, E, SE, SW, W, NW."""
    row, col = divmod(tile, 0x6C)
    parity = row & 1
    if parity == 0:
        neighbors = [
            tile - 0x6C,
            tile + 1,
            tile + 0x6C,
            tile + 0x6B,
            tile - 1,
            tile - 0x6D,
        ]
    else:
        neighbors = [
            tile - 0x6B,
            tile + 1,
            tile + 0x6D,
            tile + 0x6C,
            tile - 1,
            tile - 0x6C,
        ]
    if col < 0x6B:
        if col == 0:
            if wrap == 0:
                neighbors[4] = tile + 0x6B
                if parity == 0:
                    neighbors[5] = tile - 1
                    neighbors[3] = tile + 0xD7
            else:
                neighbors[4] = neighbors[3] = neighbors[5] = -1
    elif wrap == 0:
        neighbors[1] = tile - 0x6B
        if parity != 0:
            neighbors[2] = tile + 1
            neighbors[0] = tile - 0xD7
    else:
        neighbors[1] = neighbors[0] = neighbors[2] = -1
    if row > 0x3A:
        neighbors[2] = neighbors[3] = -1
        return neighbors
    if row == 0:
        neighbors[0] = neighbors[5] = -1
    return neighbors


def _clear_tile_yield_sources(
    session: GdbSession, snapshot: _TerrainSnapshot, tile: int
) -> None:
    """Mirror ClearTileYieldSources: blank both resource edges, and zero the
    province dev-count row when this tile is the province's city tile."""
    terrain_base = snapshot.terrain_base
    record = terrain_base + tile * _TERRAIN_RECORD_STRIDE
    session.assign(f"*(signed char*)0x{record + 0x11:08x}", -1)
    session.assign(f"*(signed char*)0x{record + 0x12:08x}", -1)
    province = struct.unpack(
        "<h",
        session.read_memory(record + 0x14, 2),
    )[0]
    if 0 <= province < _PROVINCE_COUNT:
        province_record = snapshot.province_base + province * _PROVINCE_STRIDE
        city_tile = struct.unpack(
            "<h", session.read_memory(province_record + 0x04, 2)
        )[0]
        if city_tile == tile:
            session.write_memory(province_record + 0x82, b"\x00" * 20)


def _drive_yield_rebuild(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    nation = _nation_pointer(session, _s16(session, sim_mgr + 0x2E))
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    _invoke_virtual(
        session, nation, _VT_REBUILD_YIELD, records, occurrences,
        breakpoint_roles,
    )
    result = _capture_trade_phase(session)
    result["civilians"] = _capture_civilians_phase(session)["civilians"]
    return result


def _drive_yield_rebuild_clamps(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    nation = _nation_pointer(session, 0)
    if nation == 0:
        raise RuntimeError("retail fixture has no nation at slot 0")
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    snapshot = _TerrainSnapshot(session, map_state)
    snapshot.refresh_tiles()
    snapshot.refresh_provinces()
    city = _u32(session, nation + 0x894)
    town = _u32(session, city + 0xB0)
    home_tile = _s16(session, town + 0x14)
    wrap = _u8(session, map_state + 0x20)
    _clear_tile_yield_sources(session, snapshot, home_tile)
    for neighbor in _neighbor_tile_array(home_tile, wrap):
        if neighbor != -1:
            _clear_tile_yield_sources(session, snapshot, neighbor)
    session.assign(f"*(unsigned char*)0x{town + 0x4C:08x}", 0)
    session.assign(f"*(signed char*)0x{town + 0x4D:08x}", 0)
    session.assign(f"*(unsigned char*)0x{town + 0x4F:08x}", 1)
    home_record = snapshot.terrain_base + home_tile * _TERRAIN_RECORD_STRIDE
    session.assign(f"*(signed char*)0x{home_record + 0x13:08x}", 1)
    session.assign(f"*(signed char*)0x{home_record + 0x0C:08x}", 3)
    session.assign(
        f"*(signed char*)0x{home_record + 0x11:08x}", _RESOURCE_FISH
    )
    session.assign(
        f"*(signed char*)0x{home_record + 0x12:08x}", _RESOURCE_COTTON
    )
    session.write_memory(nation + 0x10E, b"\x00" * 46)
    session.write_memory(nation + 0x13C, b"\x00" * 46)
    session.assign(
        f"*(short*)0x{nation + 0x13C + _RESOURCE_FISH * 2:08x}", 4
    )
    session.assign(
        f"*(short*)0x{nation + 0x13C + _RESOURCE_COTTON * 2:08x}", 6
    )
    session.assign(f"*(short*)0x{nation + 0xA8:08x}", 10)
    _invoke_virtual(
        session, nation, _VT_REBUILD_YIELD, records, occurrences,
        breakpoint_roles,
    )
    result = _capture_trade_phase(session)
    result["civilians"] = _capture_civilians_phase(session)["civilians"]
    return result


def _drive_yield_rebuild_multiple_towns(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    nation = _nation_pointer(session, 0)
    if nation == 0:
        raise RuntimeError("retail fixture has no nation at slot 0")
    city = _u32(session, nation + 0x894)
    home_town = _u32(session, city + 0xB0)
    session.assign(f"*(signed char*)0x{home_town + 0x4D:08x}", 0)
    session.assign(f"*(unsigned char*)0x{home_town + 0x4F:08x}", 1)
    session.assign(f"*(unsigned char*)0x{home_town + 0x4C:08x}", 0)
    out_slot = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(4,),
    )
    session.assign(f"*(unsigned int*)0x{out_slot:08x}", 0)
    _invoke_virtual(
        session,
        nation,
        _VT_TRANSPORT_INFLUENCE,
        records,
        occurrences,
        breakpoint_roles,
        args=(out_slot,),
    )
    influence_map = _u32(session, out_slot)
    if influence_map == 0:
        raise RuntimeError(
            "retail transport influence map was not returned"
        )
    tiles_map = session.read_memory(influence_map, _TILE_COUNT)
    snapshot = _TerrainSnapshot(session, _u32(session, _GLOBAL_MAP_STATE))
    snapshot.refresh_tiles()
    outpost_tile = -1
    for tile in range(_TILE_COUNT):
        if (
            tiles_map[tile] == 0
            and snapshot.tile_field(tile, 0x04, "<b") == 0
        ):
            outpost_tile = tile
            break
    if outpost_tile < 0:
        raise RuntimeError(
            "retail fixture has no disconnected owned tile for a second town"
        )
    name_buffer = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(16,),
    )
    session.write_memory(name_buffer, b"Outpost\x00")
    outpost = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_TTOWN_SIZE,),
    )
    _invoke_thiscall(
        session, _FN_TTOWN_CTOR, outpost, records, occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _FN_TTOWN_ITOWN,
        outpost,
        records,
        occurrences,
        breakpoint_roles,
        args=(name_buffer, outpost_tile, 0, 0),
    )
    session.assign(f"*(unsigned char*)0x{outpost + 0x4E:08x}", 0)
    session.assign(f"*(unsigned char*)0x{outpost + 0x4C:08x}", 1)
    town_list = _u32(session, nation + 0x898)
    _invoke_virtual(
        session,
        town_list,
        _VT_LIST_ADD_TAIL,
        records,
        occurrences,
        breakpoint_roles,
        args=(outpost,),
    )
    _invoke_virtual(
        session, nation, _VT_REBUILD_YIELD, records, occurrences,
        breakpoint_roles,
    )
    result = _capture_trade_phase(session)
    result["civilians"] = _capture_civilians_phase(session)["civilians"]
    return result


def _drive_owned_region_development(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    nation = _nation_pointer(session, _s16(session, sim_mgr + 0x2E))
    region_id = _seed_city_transport(session, seed_pending_action=False)
    _invoke_virtual(
        session, nation, _VT_ADVANCE_REGION_DEV, records, occurrences,
        breakpoint_roles,
    )
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    record = _u32(session, map_state + 0x10) + region_id * _PROVINCE_STRIDE
    result = _capture_trade_phase(session)
    result["civilians"] = _capture_civilians_phase(session)["civilians"]
    result["provinces"] = {
        "province": region_id,
        "owner": _s8(session, record),
        "dev_stage": _s8(session, record + 0x02),
        "last_turn": _s16(session, record + 0x06),
        "dev_counts": list(
            struct.unpack("<10h", session.read_memory(record + 0x82, 20))
        ),
    }
    return result


# --- specialist_recruitment / growth retail drives ------------------------------
# RunSpecialistRecruitment builds a specialist TUnitOrder on the active nation's
# city (operator new + ctor vptr store + IUnitOrder + quantity + Produce).
# RunNavyGrowthPending / RunArmyGrowthSelectedGeneral set a pending-action byte
# and run TSimMgr::DoCityAndTransport, the latter after
# TTechMgr::ActivateSlotAndUpdateUI(kMilitaryUnitGeneralEra2).

_UNIT_ORDER_SIZE = 0x5C
_UNIT_ORDER_CTOR = 0x004B6F70
_UNIT_ORDER_INIT = 0x004B6FE0
_UNIT_ORDER_PRODUCE = 0x004B73B0
_TECH_ACTIVATE_SLOT = 0x005B0340
_MILITARY_UNIT_GENERAL_ERA2 = 28
_PENDING_ACTION_BY_ACTION = 0x8C8


def _drive_specialist_recruitment(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    nation = _nation_pointer(session, _s16(session, sim_mgr + 0x2E))
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    city = _u32(session, nation + 0x894)
    if city == 0:
        raise RuntimeError("retail active nation has no city")
    order = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_UNIT_ORDER_SIZE,),
    )
    _invoke_thiscall(
        session,
        _UNIT_ORDER_CTOR,
        order,
        records,
        occurrences,
        breakpoint_roles,
    )
    _invoke_thiscall(
        session,
        _UNIT_ORDER_INIT,
        order,
        records,
        occurrences,
        breakpoint_roles,
        args=(city, 24, -1, 0, -1, 0, 0, 4, 1),
    )
    session.assign(f"*(short*)0x{order + 0x04:08x}", 1)
    _invoke_thiscall(
        session,
        _UNIT_ORDER_PRODUCE,
        order,
        records,
        occurrences,
        breakpoint_roles,
    )
    return _capture_civilians_phase(session)


def _drive_navy_growth_pending(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_slot = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, active_slot)
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    if (
        _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD) != 0
        or _u32(session, _NAVY_SECONDARY_ORDER_LIST_HEAD) != 0
    ):
        raise RuntimeError("retail fixture already has navy objects")
    zone = _invoke_thiscall(
        session,
        _FIND_FIRST_PORT_ZONE,
        _u32(session, _OCEAN_SINGLETON),
        records,
        occurrences,
        breakpoint_roles,
        args=(active_slot,),
    )
    if zone == 0:
        raise RuntimeError(
            "retail fixture has no port zone for the active nation"
        )
    session.assign(
        f"*(signed char*)0x{nation + _PENDING_ACTION_BY_ACTION:08x}", 0x32
    )
    _invoke_thiscall(
        session,
        _DO_CITY_AND_TRANSPORT,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    return _capture_military_phase(session)


def _drive_army_growth_selected_general(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_slot = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, active_slot)
    tech_mgr = _u32(session, _TECH_MGR)
    if nation == 0 or tech_mgr == 0:
        raise RuntimeError("retail loaded player has no active nation")
    session.assign(
        f"*(signed char*)0x{nation + _PENDING_ACTION_BY_ACTION + 1:08x}",
        0x32,
    )
    _invoke_thiscall(
        session,
        _TECH_ACTIVATE_SLOT,
        tech_mgr,
        records,
        occurrences,
        breakpoint_roles,
        args=(_MILITARY_UNIT_GENERAL_ERA2, active_slot),
    )
    _invoke_thiscall(
        session,
        _DO_CITY_AND_TRANSPORT,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    return _capture_military_phase(session)


# --- season_advance_clears_status_flags retail drive ---------------------------
# Mirrors RunSeasonAdvanceClearsStatusFlags: seed the pre-transition turn
# fields, then set turnStateCode=0x11/flags=0 and call TSimMgr::AdvanceSeason.

_ADVANCE_SEASON = 0x0057D950


def _drive_season_advance(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 4)
    session.assign(f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}", 0x51)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x10)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x11)
    session.assign(f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}", 0)
    _invoke_thiscall(
        session,
        _ADVANCE_SEASON,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )


def _capture_turn_state(session: GdbSession) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "dispatched_event": _current_turn_event(session),
    }


def _current_turn_event(session: GdbSession) -> int:
    view_mgr = _u32(session, 0x006A21BC)
    return _s16(session, view_mgr + 0x04) if view_mgr != 0 else -1


# --- elimination_phase_with_landed_great_powers retail drive -------------------
# Mirrors RunEliminationPhaseWithLandedGreatPowers: player-elimination check via
# the active nation's encoded slot, removal of region-less majors, region-less
# minor notifications, then the victory/eliminated/continue outcome.

# Runs the real case-0x19 elimination/game-over step of
# AdvanceGlobalTurnStateMachine: player-loss check, region-less major removal,
# minor-slot status updates, then victory/next-phase dispatch.

_COUNTRY_ENCODED_SLOT = 0x0E

# --- turn_alerts_skip_first_economic_turn retail drive -------------------------
# Mirrors RunTurnAlertsSkipFirstEconomicTurn: economicTurn = 1 forces
# ShowTurnAlertsForActiveNation's first-turn early return.

_SHOW_TURN_ALERTS = 0x00502B60


def _drive_turn_alerts_first(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 1)
    shown = (
        _invoke_thiscall(
            session,
            _SHOW_TURN_ALERTS,
            sim_mgr,
            records,
            occurrences,
            breakpoint_roles,
        )
        & 0xFF
    )
    return {"shown": shown, **_capture_turn_state(session)}


# --- turn_alerts_later_turn retail drive ---------------------------------------
# Mirrors RunTurnAlertsLaterTurn: economicTurn=3 with the turn-alert gate open.
# The native run records each displayed alert's body string row instead of
# posing the modal; the retail side reproduces that by breaking on
# TSimMgr::GetString (to track the last fetched 0x2753 row) and on
# TViewMgr::ModalMessage (to record the body row then return early from the
# callee, skipping the dialog entirely).

_GET_STRING_BODY = 0x00580760
_MODAL_MESSAGE = 0x005D5C40
_MODAL_MESSAGE_STACK_ARGS = 24
_LAST_TURN_ALERT_TICK = 0x006A31C0
_TURN_COOLDOWN_DEFER = 0x006A43C4
_DIPLOMACY_LAST_EFFORT_TURN = 0x790


def _drive_turn_alerts_later(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    diplomacy_mgr = _u32(session, _DIPLOMACY_MGR)
    session.assign(f"*(short*)0x{sim_mgr + 0x2C:08x}", 3)
    session.assign(f"*(short*)0x{sim_mgr + 0x58:08x}", 1)
    session.assign(f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}", 0x1010)
    session.assign(
        f"*(short*)0x{diplomacy_mgr + _DIPLOMACY_LAST_EFFORT_TURN:08x}", 0
    )
    session.assign(f"*(int*)0x{_LAST_TURN_ALERT_TICK:08x}", 0)
    session.assign(f"*(short*)0x{_TURN_COOLDOWN_DEFER:08x}", 0)

    stack = _eval_int(session, "$esp")
    return_address = _eval_int(session, "$eip")
    return_breakpoint = session.set_breakpoint(return_address)
    getstring_breakpoint = session.set_breakpoint(_GET_STRING_BODY)
    modal_breakpoint = session.set_breakpoint(_MODAL_MESSAGE)
    alerts: list[int] = []
    last_row = -1
    try:
        session.assign(f"*(unsigned int*)0x{stack - 4:08x}", return_address)
        session.assign("$esp", stack - 4)
        session.assign("$eip", _SHOW_TURN_ALERTS)
        session.continue_inferior()
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            stop = session.wait_for_stop(
                min(1.0, deadline - time.monotonic())
            )
            if stop is None:
                if session.process.poll() is not None:
                    raise RuntimeError(
                        "debugged game exited before the injected call returned"
                    )
                continue
            if is_terminal_stop(stop):
                raise RuntimeError(
                    "debugged game exited before the injected call returned"
                )
            if stop.reason == "breakpoint-hit":
                number = stop.breakpoint_number or ""
                if number == return_breakpoint:
                    break
                if number == getstring_breakpoint:
                    frame = _eval_int(session, "$esp")
                    if (
                        _eval_int(
                            session, f"*(int*)0x{frame + 4:08x}"
                        )
                        == 0x2753
                    ):
                        last_row = (
                            _eval_int(
                                session, f"*(int*)0x{frame + 8:08x}"
                            )
                            & 0xFFFF
                        )
                    session.continue_inferior()
                    continue
                if number == modal_breakpoint:
                    alerts.append(last_row)
                    frame = _eval_int(session, "$esp")
                    session.assign(
                        "$eip", _u32(session, frame)
                    )
                    session.assign(
                        "$esp", frame + 4 + _MODAL_MESSAGE_STACK_ARGS
                    )
                    session.continue_inferior()
                    continue
                role = breakpoint_roles.get(number)
                if (
                    role is not None
                    and role[0] == "probe"
                    and role[1] is not None
                ):
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
        else:
            session.interrupt_and_capture("injected-call-timeout")
            raise RuntimeError(
                "timed out waiting for injected call to return"
            )
        session.assign("$esp", stack)
    finally:
        session.delete_breakpoint(return_breakpoint)
        session.delete_breakpoint(getstring_breakpoint)
        session.delete_breakpoint(modal_breakpoint)
    return {"alerts": alerts, **_capture_turn_state(session)}


# --- great_power_pressure_* retail drives --------------------------------------
# Mirrors RunGreatPowerPressureHumanDebt / RunGreatPowerPressureAiNoop:
# UpdateGreatPowerPressureStateAndDispatchEscalationMessage is vtable slot 0xaf
# (byte offset 0x2bc); TAutoGreatPower's override is a hard-coded 0.

_PRESSURE_UPDATE_VTABLE = 0x2BC
_COUNTRY_TREASURY = 0x10
_GREAT_POWER_BUDGET_BASE = 0x8F0
_GREAT_POWER_ESCALATION = 0x8F4
_GREAT_POWER_PRESSURE = 0x8FC


def _capture_pressure_nations(session: GdbSession) -> list[object]:
    nations: list[object] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        nations.append(
            {
                "treasury": _s32(session, nation + _COUNTRY_TREASURY),
                "budget_base": _s32(
                    session, nation + _GREAT_POWER_BUDGET_BASE
                ),
                "escalation": _eval_int(
                    session,
                    f"*(signed char*)0x{nation + _GREAT_POWER_ESCALATION:08x}",
                ),
                "pressure": _eval_int(
                    session,
                    f"*(signed char*)0x{nation + _GREAT_POWER_PRESSURE:08x}",
                ),
            }
        )
    return nations


def _drive_pressure_human_debt(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(int*)0x{sim_mgr + 0x40:08x}", 1)
    active_nation = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, active_nation)
    if nation == 0:
        raise ValueError("retail active nation pointer is null")
    session.assign(f"*(int*)0x{nation + _COUNTRY_TREASURY:08x}", -100)
    session.assign(
        f"*(int*)0x{nation + _GREAT_POWER_BUDGET_BASE:08x}", 50000
    )
    session.assign(
        f"*(signed char*)0x{nation + _GREAT_POWER_ESCALATION:08x}", 10
    )
    session.assign(
        f"*(signed char*)0x{nation + _GREAT_POWER_PRESSURE:08x}", 0
    )
    lost = 0
    for slot in range(_MAJOR_NATION_COUNT - 1, -1, -1):
        slot_nation = _nation_pointer(session, slot)
        if slot_nation == 0:
            continue
        if (
            _invoke_virtual(
                session,
                slot_nation,
                _PRESSURE_UPDATE_VTABLE,
                records,
                occurrences,
                breakpoint_roles,
            )
            & 0xFF
            != 0
        ):
            lost = 1
    return {
        "lost": lost,
        "nations": _capture_pressure_nations(session),
        **_capture_turn_state(session),
    }


def _drive_pressure_ai_noop(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_nation = _s16(session, sim_mgr + 0x2E)
    ai_slot = 1 if active_nation == 0 else 0
    nation = _nation_pointer(session, ai_slot)
    if nation == 0:
        raise ValueError("retail AI nation pointer is null")
    session.assign(f"*(int*)0x{nation + _COUNTRY_TREASURY:08x}", -10000)
    session.assign(
        f"*(signed char*)0x{nation + _GREAT_POWER_PRESSURE:08x}", 4
    )
    lost = (
        _invoke_virtual(
            session,
            nation,
            _PRESSURE_UPDATE_VTABLE,
            records,
            occurrences,
            breakpoint_roles,
        )
        & 0xFF
    )
    return {
        "lost": lost,
        "nations": _capture_pressure_nations(session),
        **_capture_turn_state(session),
    }


def _drive_elimination_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x19)
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
        _ADVANCE_TURN_STATE,
        sim_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    eligibility = []
    nation_encoded = []
    for slot in range(_MAJOR_NATION_COUNT):
        terrain = _eval_int(
            session,
            f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * slot:08x}",
        )
        if terrain == 0:
            eligibility.append(-1)
        else:
            code = _s16(session, terrain + _COUNTRY_ENCODED_SLOT)
            eligibility.append(1 if code < 100 or code > 199 else 0)
        nation = _nation_pointer(session, slot)
        nation_encoded.append(
            _s16(session, nation + _COUNTRY_ENCODED_SLOT)
            if nation != 0
            else -1
        )
    return {
        "eligibility": eligibility,
        "nation_encoded": nation_encoded,
        "nation_status": _capture_nation_status(session),
        "rng": _capture_rng_state(
            session, records, occurrences, breakpoint_roles
        ),
        **_capture_turn_state(session),
    }


def _capture_nation_status(
    session: GdbSession,
) -> list[dict[str, int] | None]:
    statuses: list[dict[str, int] | None] = []
    for slot in range(0x17):
        nation = _u32(session, _TERRAIN_TABLE + 4 * slot)
        if nation == 0:
            statuses.append(None)
            continue
        statuses.append(
            {
                "encoded_slot": _s16(
                    session, nation + _COUNTRY_ENCODED_SLOT
                ),
                "owned_region_count": len(
                    _longint_list_entries(
                        session, _u32(session, nation + 0x90)
                    )
                ),
            }
        )
    return statuses


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


_STRATEGIC_NAVAL_BATTLE_MATRIX = (
    {
        "name": "left_fails_admiral_boundary",
        "seed": 0x1234,
        "left": ((3,), 0, 100, 0, 0),
        "right": ((3,), 0, 100, 0, 100),
        "convergence": "only_left_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "left_fails_tier_gap",
        "seed": 0x1234,
        "left": ((3,), 0, 500, 0, 0),
        "right": ((7,), 0, 500, 0, 0),
        "convergence": "only_left_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "left_fails_fleet_size",
        "seed": 50,
        "left": ((4,), 1, 1600, 0, 400),
        "right": ((4, 4, 7), 0, 500, 0, 0),
        "convergence": "only_left_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "left_fails_mixed_tiers",
        "seed": 1,
        "left": ((7, 11), 0, 500, 0, 200),
        "right": ((7, 8, 11), 1, 500, 0, 100),
        "convergence": "only_left_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "right_fails_admiral_boundary",
        "seed": 0x1234,
        "left": ((3,), 0, 100, 0, 400),
        "right": ((3,), 0, 100, 0, 200),
        "convergence": "only_right_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "right_fails_tier_gap",
        "seed": 0x1234,
        "left": ((7,), 0, 500, 0, 0),
        "right": ((3,), 0, 500, 0, 0),
        "convergence": "only_right_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "right_fails_mixed_tiers",
        "seed": 10,
        "left": ((8, 9, 13), 1, 500, 0, 100),
        "right": ((9, 11, 11), 2, 1000, 0, 100),
        "convergence": "only_right_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "right_fails_fleet_size",
        "seed": 999,
        "left": ((4, 7, 7, 7), 2, 500, 0, 200),
        "right": ((8,), 1, 500, 0, 200),
        "convergence": "only_right_fails",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "both_fail_tier_one",
        "seed": 999,
        "left": ((3,), 0, 100, 0, 0),
        "right": ((3,), 0, 100, 0, 0),
        "convergence": "both_fail",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "both_fail_tier_two",
        "seed": 10,
        "left": ((8,), 0, 500, 0, 0),
        "right": ((8,), 0, 500, 0, 0),
        "convergence": "both_fail",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "both_fail_admiral_boundary",
        "seed": 4,
        "left": ((4,), 0, 100, 0, 200),
        "right": ((4,), 0, 100, 0, 100),
        "convergence": "both_fail",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "both_fail_top_tiers",
        "seed": 2,
        "left": ((11, 11, 12), 0, 500, 0, 100),
        "right": ((11, 11, 13), 0, 500, 0, 200),
        "convergence": "both_fail",
        "resolution": "tier_exhaustion",
    },
    {
        "name": "left_eliminated_tier_one",
        "seed": 0x1234,
        "left": ((3,), 0, 1, 0, 200),
        "right": ((3, 3), 0, 1, 0, 400),
        "convergence": "only_left_fails",
        "resolution": "left_eliminated",
    },
    {
        "name": "left_eliminated_tier_two",
        "seed": 0x1234,
        "left": ((7,), 0, 1, 0, 0),
        "right": ((7, 7), 0, 1, 0, 0),
        "convergence": "only_left_fails",
        "resolution": "left_eliminated",
    },
    {
        "name": "left_eliminated_weight_boundary",
        "seed": 999,
        "left": ((8,), 0, 1, 0, 0),
        "right": ((8, 8), 0, 1, 0, 0),
        "convergence": "only_left_fails",
        "resolution": "left_eliminated",
    },
    {
        "name": "right_eliminated_tier_one",
        "seed": 0x1234,
        "left": ((3, 3), 0, 1, 0, 0),
        "right": ((3,), 0, 1, 0, 0),
        "convergence": "only_right_fails",
        "resolution": "right_eliminated",
    },
    {
        "name": "right_eliminated_tier_two",
        "seed": 0x1234,
        "left": ((7, 7), 0, 1, 0, 0),
        "right": ((7,), 0, 1, 0, 0),
        "convergence": "only_right_fails",
        "resolution": "right_eliminated",
    },
    {
        "name": "right_eliminated_weight_boundary",
        "seed": 2,
        "left": ((8, 8), 0, 1, 0, 0),
        "right": ((8,), 0, 1, 0, 0),
        "convergence": "only_right_fails",
        "resolution": "right_eliminated",
    },
    {
        "name": "both_eliminated_admiral_boundary",
        "seed": 0x1234,
        "left": ((3,), 0, 1, 0, 100),
        "right": ((3,), 0, 1, 0, 0),
        "convergence": "only_right_fails",
        "resolution": "both_eliminated",
    },
    {
        "name": "both_eliminated_neither_fails",
        "seed": 0x1234,
        "left": ((3,), 2, 1, 0, 0),
        "right": ((3,), 2, 1, 0, 0),
        "convergence": "neither_fails",
        "resolution": "both_eliminated",
    },
)


def _create_strategic_battle_fleet(
    session: GdbSession,
    zone: int,
    nation: int,
    side: tuple[tuple[int, ...], int, int, int, int],
    case_index: int,
    side_name: str,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> tuple[int, list[int]]:
    types, aggression, strength, experience, admiral_experience = side
    force = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_TTASKFORCE_SIZE,),
    )
    _invoke_thiscall(
        session,
        _TTASKFORCE_CTOR,
        force,
        records,
        occurrences,
        breakpoint_roles,
        args=(zone, nation),
    )
    session.assign(f"*(char*)0x{force + 0x26:08x}", 0)
    _invoke_thiscall(
        session,
        _TTASKFORCE_SET_AGGRESSION,
        force,
        records,
        occurrences,
        breakpoint_roles,
        args=(aggression,),
    )
    ships = []
    for index, ship_type in enumerate(types):
        ship = _new_ship(
            session,
            ship_type,
            zone,
            nation,
            f"matrix-{case_index:02d}-{side_name}{index}",
            records,
            occurrences,
            breakpoint_roles,
        )
        session.assign(f"*(short*)0x{ship + 0x1C:08x}", strength)
        session.assign(f"*(short*)0x{ship + 0x30:08x}", experience)
        _invoke_thiscall(
            session,
            _TTASKFORCE_ADD,
            force,
            records,
            occurrences,
            breakpoint_roles,
            args=(ship,),
        )
        ships.append(ship)
    _invoke_thiscall(
        session,
        _TTASKFORCE_ELECT_FLAGSHIP,
        force,
        records,
        occurrences,
        breakpoint_roles,
    )
    admiral = _invoke_thiscall(
        session,
        _OPERATOR_NEW,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(_TADMIRAL_SIZE,),
    )
    _invoke_thiscall(
        session,
        _TADMIRAL_CTOR,
        admiral,
        records,
        occurrences,
        breakpoint_roles,
        args=(nation,),
    )
    session.assign(f"*(short*)0x{admiral + 0x10:08x}", admiral_experience)
    _invoke_thiscall(
        session,
        _TADMIRAL_ASSIGN_TO_SHIP,
        admiral,
        records,
        occurrences,
        breakpoint_roles,
        args=(_u32(session, force + 0x14),),
    )
    return force, ships


def _strategic_battle_live_ships(
    session: GdbSession, force: int
) -> set[int]:
    live = set()
    link = _u32(session, force + 0x10)
    while link != 0:
        live.add(_u32(session, link))
        link = _u32(session, link + 0x04)
    return live


def _capture_strategic_battle_fleet(
    session: GdbSession,
    force: int,
    ships: list[int],
    side: tuple[tuple[int, ...], int, int, int, int],
) -> dict[str, object]:
    types, aggression, strength, experience, admiral_experience = side
    live = _strategic_battle_live_ships(session, force)
    ship_rows = []
    live_admiral = 0
    for ship_type, ship in zip(types, ships, strict=True):
        alive = ship in live
        row = {
            "type": ship_type,
            "alive": alive,
            "strength": _s16(session, ship + 0x1C) if alive else None,
            "experience": _s16(session, ship + 0x30) if alive else None,
        }
        if alive and _u32(session, ship + 0x20) != 0:
            live_admiral = _u32(session, ship + 0x20)
        ship_rows.append(row)
    return {
        "aggression": aggression,
        "initial_strength": strength,
        "initial_experience": experience,
        "initial_admiral_experience": admiral_experience,
        "defeated": _u8(session, force + 0x26) != 0,
        "admiral_experience": (
            _s16(session, live_admiral + 0x10) if live_admiral != 0 else None
        ),
        "ships": ship_rows,
    }


def _free_strategic_battle_fleet(
    session: GdbSession,
    force: int,
    ships: list[int],
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    live = _strategic_battle_live_ships(session, force)
    _invoke_thiscall(
        session,
        _TTASKFORCE_FREE,
        force,
        records,
        occurrences,
        breakpoint_roles,
    )
    for ship in ships:
        if ship in live:
            _invoke_thiscall(
                session,
                _TSHIP_FREE,
                ship,
                records,
                occurrences,
                breakpoint_roles,
            )


def _drive_strategic_naval_battle_matrix(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_nation = _s16(session, sim_mgr + 0x2E)
    hostile_nation = next(
        slot
        for slot in range(_MAJOR_NATION_COUNT)
        if slot != active_nation and _nation_pointer(session, slot) != 0
    )
    zone = _find_unoccupied_zone(session)
    navy_mgr = _u32(session, _NAVY_ORDER_MANAGER)
    action_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    reports = _u32(session, action_mgr + 0x04)
    rows = []
    for case_index, test_case in enumerate(_STRATEGIC_NAVAL_BATTLE_MATRIX):
        left, left_ships = _create_strategic_battle_fleet(
            session,
            zone,
            active_nation,
            test_case["left"],
            case_index,
            "l",
            records,
            occurrences,
            breakpoint_roles,
        )
        right, right_ships = _create_strategic_battle_fleet(
            session,
            zone,
            hostile_nation,
            test_case["right"],
            case_index,
            "r",
            records,
            occurrences,
            breakpoint_roles,
        )
        report_count = _eval_int(session, f"*(int*)0x{reports + 0x08:08x}")
        _invoke_thiscall(
            session,
            _SRAND,
            0,
            records,
            occurrences,
            breakpoint_roles,
            args=(test_case["seed"],),
        )
        _invoke_thiscall(
            session,
            _RESOLVE_STRATEGIC_BATTLE,
            navy_mgr,
            records,
            occurrences,
            breakpoint_roles,
            args=(left, right),
        )
        if _eval_int(session, f"*(int*)0x{reports + 0x08:08x}") != report_count + 1:
            raise RuntimeError("strategic naval battle did not append one report")
        report_data = _u32(session, reports + 0x04)
        report = _u32(session, report_data + report_count * 4)
        participant = _s8(session, report + 0x02)
        left_row = _capture_strategic_battle_fleet(
            session, left, left_ships, test_case["left"]
        )
        right_row = _capture_strategic_battle_fleet(
            session, right, right_ships, test_case["right"]
        )
        rows.append(
            {
                "case": test_case["name"],
                "seed": test_case["seed"],
                "convergence": test_case["convergence"],
                "resolution": test_case["resolution"],
                "participant": participant,
                "winner": (
                    "left" if participant == 0 else "right" if participant == 1 else "draw"
                ),
                "left_defeated": left_row["defeated"],
                "right_defeated": right_row["defeated"],
                "left": left_row,
                "right": right_row,
            }
        )
        _free_strategic_battle_fleet(
            session, left, left_ships, records, occurrences, breakpoint_roles
        )
        _free_strategic_battle_fleet(
            session, right, right_ships, records, occurrences, breakpoint_roles
        )
    return {"cases": rows}


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


def _production_navy_ship_survived(session: GdbSession, expected: int) -> bool:
    ship = _u32(session, _NAVY_PRIMARY_ORDER_LIST_HEAD)
    while ship != 0:
        if ship == expected:
            return True
        ship = _u32(session, ship + 0x24)
    return False


def _production_task_force_remains_queued(
    session: GdbSession, expected: int
) -> bool:
    navy_mgr = _u32(session, _NAVY_ORDER_MANAGER)
    force = _u32(session, navy_mgr + 0x04)
    while force != 0:
        if force == expected:
            return True
        force = _u32(session, force + 0x2C)
    return False


def _capture_production_naval_side(
    session: GdbSession, force: int, ship: int, admiral: int
) -> dict[str, object]:
    survived = _production_navy_ship_survived(session, ship)
    queued = _production_task_force_remains_queued(session, force)
    return {
        "survived": survived,
        "force_queued": queued,
        "defeated": bool(_u8(session, force + 0x26)) if queued else not survived,
        "strength": _s16(session, ship + 0x1C) if survived else None,
        "experience": _s16(session, ship + 0x30) if survived else None,
        "admiral_experience": (
            _s16(session, admiral + 0x10)
            if survived and _u32(session, ship + 0x20) == admiral
            else -1
        )
        if survived
        else None,
    }


def _capture_production_naval_report_side(
    session: GdbSession, report: int, side: int
) -> list[dict[str, int]]:
    ships = []
    count = _u16(session, report + 0x24A + 2 * side)
    records = _u32(session, report + 0x250 + 4 * side)
    for index in range(count):
        child = records + 0x2C * index
        ships.append(
            {
                "type": _s16(session, child),
                "strength": _s16(session, child + 0x02),
                "experience_bucket": _u8(session, child + 0x24),
            }
        )
    return ships


def _drive_military_phase_naval_encounter(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    attacker_type: int = 3,
    defender_type: int = 3,
    tier_exhaustion: bool = False,
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
    attacker_ship = _new_ship(
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
    defender_ship = _new_ship(
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
    attacker_admiral = 0
    defender_admiral = 0
    report_count_before = 0
    if tier_exhaustion:
        session.assign(f"*(short*)0x{attacker_ship + 0x1C:08x}", 100)
        session.assign(f"*(short*)0x{attacker_ship + 0x30:08x}", 0)
        session.assign(f"*(short*)0x{defender_ship + 0x1C:08x}", 100)
        session.assign(f"*(short*)0x{defender_ship + 0x30:08x}", 0)
        _invoke_thiscall(
            session,
            _TTASKFORCE_SET_AGGRESSION,
            attacker,
            records,
            occurrences,
            breakpoint_roles,
            args=(1,),
        )
        _invoke_thiscall(
            session,
            _TTASKFORCE_SET_AGGRESSION,
            defender,
            records,
            occurrences,
            breakpoint_roles,
            args=(1,),
        )
        attacker_admiral = _invoke_thiscall(
            session,
            _OPERATOR_NEW,
            0,
            records,
            occurrences,
            breakpoint_roles,
            args=(_TADMIRAL_SIZE,),
        )
        defender_admiral = _invoke_thiscall(
            session,
            _OPERATOR_NEW,
            0,
            records,
            occurrences,
            breakpoint_roles,
            args=(_TADMIRAL_SIZE,),
        )
        _invoke_thiscall(
            session,
            _TADMIRAL_CTOR,
            attacker_admiral,
            records,
            occurrences,
            breakpoint_roles,
            args=(active_nation,),
        )
        _invoke_thiscall(
            session,
            _TADMIRAL_CTOR,
            defender_admiral,
            records,
            occurrences,
            breakpoint_roles,
            args=(hostile_nation,),
        )
        session.assign(f"*(short*)0x{attacker_admiral + 0x10:08x}", 0)
        session.assign(f"*(short*)0x{defender_admiral + 0x10:08x}", 100)
        _invoke_thiscall(
            session,
            _TADMIRAL_ASSIGN_TO_SHIP,
            attacker_admiral,
            records,
            occurrences,
            breakpoint_roles,
            args=(attacker_ship,),
        )
        _invoke_thiscall(
            session,
            _TADMIRAL_ASSIGN_TO_SHIP,
            defender_admiral,
            records,
            occurrences,
            breakpoint_roles,
            args=(defender_ship,),
        )
        map_context_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
        reports = _u32(session, map_context_mgr + 0x04)
        report_count_before = _u32(session, reports + 0x08)
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
    if tier_exhaustion:
        session.assign(f"*(short*)0x{sim_mgr + 0x4A:08x}", 0)
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
    if tier_exhaustion:
        map_context_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
        reports = _u32(session, map_context_mgr + 0x04)
        report_count = _u32(session, reports + 0x08)
        if report_count != report_count_before + 1:
            raise RuntimeError(
                "controlled production naval battle did not append one report"
            )
        report = _u32(session, _u32(session, reports + 0x04) + 4 * report_count_before)
        participant = _s8(session, report + 0x02)
        left = _capture_production_naval_side(
            session, attacker, attacker_ship, attacker_admiral
        )
        right = _capture_production_naval_side(
            session, defender, defender_ship, defender_admiral
        )
        if (
            not left["survived"]
            or not right["survived"]
            or not left["force_queued"]
            or not right["force_queued"]
            or left["strength"] != 100
            or right["strength"] != 100
            or left["defeated"] == right["defeated"]
        ):
            raise RuntimeError(
                "controlled naval battle did not exhaust tiers with both fleets afloat"
            )
        pre["naval_outcome"] = {
            "participant": participant,
            "winner": (
                "left"
                if participant == 0
                else "right"
                if participant == 1
                else "draw"
            ),
            "left": left,
            "right": right,
            "left_report_ships": _capture_production_naval_report_side(
                session, report, 0
            ),
            "right_report_ships": _capture_production_naval_report_side(
                session, report, 1
            ),
        }
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


def _drive_consecutive_turn_sequence(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunConsecutiveTurnSequence: the second-turn setup, then twelve
    full deal-book -> newspaper -> player-orders cycles through
    AdvanceGlobalTurnStateMachine (0x57da70)."""
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
    economic_turns: list[int] = []
    for _turn in range(12):
        step = 0
        state = _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}")
        while state != 0x0E and step < 32:
            _invoke_thiscall(
                session,
                _ADVANCE_TURN_STATE,
                sim_mgr,
                records,
                occurrences,
                breakpoint_roles,
            )
            step += 1
            state = _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}")
        if state != 0x0E:
            raise RuntimeError("retail turn sequence did not reach 0x0e")
        stops.append(state)
        while state != 0x12 and step < 48:
            _invoke_thiscall(
                session,
                _ADVANCE_TURN_STATE,
                sim_mgr,
                records,
                occurrences,
                breakpoint_roles,
            )
            step += 1
            state = _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}")
        if state != 0x12:
            raise RuntimeError("retail turn sequence did not reach 0x12")
        stops.append(state)
        _invoke_thiscall(
            session,
            _ADVANCE_TURN_STATE,
            sim_mgr,
            records,
            occurrences,
            breakpoint_roles,
        )
        state = _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}")
        if state != 0x05:
            raise RuntimeError("retail turn sequence did not return to 0x05")
        stops.append(state)
        economic_turns.append(_s16(session, sim_mgr + 0x2C))
    return {"stops": stops, "economic_turns": economic_turns}


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
    session: GdbSession,
    snapshot: _TerrainSnapshot,
    skip_unit: int = 0,
    skip_dest: int = -1,
) -> tuple[int, int, int]:
    """Mirror FindHostileRedeployExcluding: first unit with an adjacent
    enemy-garrisoned province, optionally skipping a unit and a destination.
    Returns (unit, destination region, defender nation slot)."""
    for slot in range(_NATION_SLOT_COUNT):
        country = _u32(session, _TERRAIN_TABLE + slot * 4)
        if country == 0:
            continue
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, country + 0x44)
        ):
            source = _s16(session, unit + 0x06)
            if unit == skip_unit or source < 0 or source >= _PROVINCE_COUNT:
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
                if dest < 0 or dest >= _PROVINCE_COUNT or dest == skip_dest:
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


def _find_uncontested_redeploy(
    session: GdbSession, snapshot: _TerrainSnapshot, skip_unit: int = 0
) -> tuple[int, int]:
    """Mirror FindUncontestedRedeploy: first unit with an adjacent
    same-owner province. Returns (unit, destination region)."""
    for slot in range(_NATION_SLOT_COUNT):
        country = _u32(session, _TERRAIN_TABLE + slot * 4)
        if country == 0:
            continue
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, country + 0x44)
        ):
            source = _s16(session, unit + 0x06)
            if unit == skip_unit or source < 0 or source >= _PROVINCE_COUNT:
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
                if struct.unpack("<b", destination[0x00:0x01])[0] == owner:
                    return unit, dest
    return 0, -1


def _issue_uncontested_redeploys(
    session: GdbSession,
    snapshot: _TerrainSnapshot,
    skip_unit: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    """Mirror IssueUncontestedRedeploys: give every unit except skip_unit a
    redeploy order to its first adjacent same-owner province."""
    issued = 0
    for slot in range(_NATION_SLOT_COUNT):
        country = _u32(session, _TERRAIN_TABLE + slot * 4)
        if country == 0:
            continue
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, country + 0x44)
        ):
            source = _s16(session, unit + 0x06)
            if unit == skip_unit or source < 0 or source >= _PROVINCE_COUNT:
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
                if struct.unpack("<b", destination[0x00:0x01])[0] == owner:
                    _invoke_thiscall(
                        session,
                        _TUNIT_SET_ORDERS,
                        unit,
                        records,
                        occurrences,
                        breakpoint_roles,
                        args=(_UNIT_ORDER_REDEPLOY, dest),
                    )
                    issued += 1
                    break
    return issued


def _stack_unit_ids(session: GdbSession, stack: int) -> list[int]:
    ids = []
    node = _u32(session, stack + 0x14)
    while node != 0:
        unit = _u32(session, node + 0x00)
        if unit != 0:
            ids.append(_eval_int(session, f"*(int*)0x{unit + 0x20:08x}"))
        node = _u32(session, node + 0x04)
    return ids


def _capture_active_battle(session: GdbSession, army_mgr: int) -> dict | None:
    """Mirror CaptureActiveBattleJson: read the cached battle stacks after
    ResolveNextMove stops on a battle view."""
    view = _u32(session, army_mgr + 0x3A4)
    ours = _u32(session, army_mgr + 0x39C)
    enemy = _u32(session, army_mgr + 0x3A0)
    if view == 0 or ours == 0 or enemy == 0:
        return None
    return {
        "province": _s16(session, enemy + 0x10),
        "attacker_nation": _s8(session, ours + 0x08),
        "defender_nation": _s8(session, enemy + 0x08),
        "attacker_units": _stack_unit_ids(session, ours),
        "defender_units": _stack_unit_ids(session, enemy),
    }


def _capture_military_positions(session: GdbSession) -> list[dict]:
    units = []
    for slot in range(_NATION_SLOT_COUNT):
        country = _u32(session, _TERRAIN_TABLE + slot * 4)
        if country == 0:
            continue
        for unit in _sorted_ptr_list_entries(
            session, _u32(session, country + 0x44)
        ):
            units.append(
                {
                    "id": _eval_int(
                        session, f"*(int*)0x{unit + 0x20:08x}"
                    ),
                    "tile": _s16(session, unit + 0x06),
                }
            )
    return units


_DO_COMBAT_MOVES = 0x004A1E40
_RESOLVE_NEXT_MOVE = 0x004A2390


def _drive_combat_moves(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    mode: str,
) -> dict[str, object]:
    """Mirror the RunCombatMoves* cases: clear orders, seed redeploys, then
    drive the production TArmyMgr::DoCombatMoves (0x4a1e40) and, for the
    sequencing modes, TArmyMgr::ResolveNextMove (0x4a2390) resume step."""
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    snapshot = _TerrainSnapshot(session, map_state)
    # TArmyStackList::Compare sorts on field6 = (class << 8) | (rand() & 0xff),
    # so FormStacks consumes rand() per stack -- pin the stream for parity.
    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )
    _clear_all_military_orders(
        session, records, occurrences, breakpoint_roles
    )
    snapshot.refresh_provinces()
    if mode == "uncontested":
        unit, dest = _find_uncontested_redeploy(session, snapshot)
        if unit == 0:
            raise RuntimeError(
                "the loaded fixture has no adjacent same-owner provinces "
                "with a stationed unit"
            )
        _invoke_thiscall(
            session,
            _TUNIT_SET_ORDERS,
            unit,
            records,
            occurrences,
            breakpoint_roles,
            args=(_UNIT_ORDER_REDEPLOY, dest),
        )
    elif mode == "battle_then_moves":
        hostile, hostile_dest, defender = _find_hostile_redeploy(
            session, snapshot
        )
        if hostile == 0:
            raise RuntimeError(
                "the loaded fixture has no adjacent enemy-garrisoned province"
            )
        if (
            _issue_uncontested_redeploys(
                session,
                snapshot,
                hostile,
                records,
                occurrences,
                breakpoint_roles,
            )
            == 0
        ):
            raise RuntimeError(
                "the loaded fixture has no later same-owner redeploy besides "
                "the hostile stack"
            )
        _force_war_between(
            session, _s16(session, hostile + 0x18), defender
        )
        _invoke_thiscall(
            session,
            _TUNIT_SET_ORDERS,
            hostile,
            records,
            occurrences,
            breakpoint_roles,
            args=(_UNIT_ORDER_REDEPLOY, hostile_dest),
        )
    else:
        first, first_dest, first_defender = _find_hostile_redeploy(
            session, snapshot
        )
        if first == 0:
            raise RuntimeError(
                "the loaded fixture has no adjacent enemy-garrisoned province"
            )
        _force_war_between(
            session, _s16(session, first + 0x18), first_defender
        )
        _invoke_thiscall(
            session,
            _TUNIT_SET_ORDERS,
            first,
            records,
            occurrences,
            breakpoint_roles,
            args=(_UNIT_ORDER_REDEPLOY, first_dest),
        )
        if mode == "two_battles":
            second, second_dest, second_defender = _find_hostile_redeploy(
                session, snapshot, skip_unit=first, skip_dest=first_dest
            )
            if second == 0:
                raise RuntimeError(
                    "the loaded fixture has no second distinct hostile stack"
                )
            _force_war_between(
                session, _s16(session, second + 0x18), second_defender
            )
            _invoke_thiscall(
                session,
                _TUNIT_SET_ORDERS,
                second,
                records,
                occurrences,
                breakpoint_roles,
                args=(_UNIT_ORDER_REDEPLOY, second_dest),
            )
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    battles = []
    _invoke_thiscall(
        session,
        _DO_COMBAT_MOVES,
        army_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    battle = _capture_active_battle(session, army_mgr)
    if battle is not None:
        battles.append(battle)
    if mode in ("two_battles", "battle_then_moves"):
        _invoke_thiscall(
            session,
            _RESOLVE_NEXT_MOVE,
            army_mgr,
            records,
            occurrences,
            breakpoint_roles,
        )
        battle = _capture_active_battle(session, army_mgr)
        if battle is not None:
            battles.append(battle)
    result = _capture_turn_state(session)
    result["battles"] = battles
    result["units"] = _capture_military_positions(session)
    return result


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


def _clear_all_military_orders(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
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
    _clear_all_military_orders(
        session, records, occurrences, breakpoint_roles
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


# --- interactive_army_battle_melee / _ranged retail drive -----------------------
# Mirrors RunInteractiveArmyBattleAttack: hostile redeploy under a forced war,
# defender made active, then a tactical loop that scans the hover-cursor state
# per tile (0x5a05a0) and dispatches the attack (0x5a3370), moves toward the
# nearest enemy (vtable slot 0x0d), or ends the action, pumping
# NextMove (0x5a0e20) back to active-nation input between steps.

_FORM_STACKS = 0x004A1F80
_RESOLVE_NEXT_MOVE = 0x004A2390
_HOVER_STATE_INDEX = 0x005A05A0
_DISPATCH_HOVER_ACTION = 0x005A3370
_MOVE_TACTICAL_VTABLE = 0x34  # TTacticalBattle slot 0x0d
_CRT_GETPTD = 0x005ED7F0
_TACTICAL_TILE_STRIDE = 0x14
_MAP_GENERATION_RNG = 0x006A38E8
_ZONE_STATUS_RNG = 0x006A5AEC


def _crt_rand_state(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    ptd = _invoke_thiscall(
        session, _CRT_GETPTD, 0, records, occurrences, breakpoint_roles
    )
    if ptd == 0:
        return 0
    return _u32(session, ptd + 0x14)


def _capture_rng_state(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, int]:
    return {
        "crt_rand": _crt_rand_state(
            session, records, occurrences, breakpoint_roles
        ),
        "map_generation": _u32(session, _MAP_GENERATION_RNG),
        "zone_status": _u32(session, _ZONE_STATUS_RNG),
    }


def _hex_tile_distance(a: int, b: int) -> int:
    row_a = a // 0x1D
    col_a = (row_a & 1) + (a % 0x1D) * 2
    row_b = b // 0x1D
    col_b = (row_b & 1) + (b % 0x1D) * 2
    if col_b < col_a:
        col_b = col_a * 2 - col_b
    if row_b < row_a:
        row_b = row_a * 2 - row_b
    row_delta = row_b - row_a
    col_a = (col_b - row_delta) - col_a
    if col_a > 0:
        return col_a // 2 + row_delta
    return row_delta


def _battle_snapshot(
    session: GdbSession,
    battle: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    record_list = _u32(session, battle + 0x20)
    units = _sorted_ptr_list_entries(session, record_list)
    units.sort(
        key=lambda unit: _u32(session, _u32(session, unit + 0x38) + 0x20)
    )
    unit_records = []
    for unit in units:
        source = _u32(session, unit + 0x38)
        unit_records.append(
            {
                "source": _s32(session, source + 0x20),
                "side": _s32(session, unit + 0x20),
                "tile": _s32(session, unit + 0x08),
                "action_points": _s32(session, unit + 0x28),
                "strength": _s32(session, unit + 0x04),
                "morale": _s32(session, unit + 0x34),
                "state": _s32(session, unit + 0x1C),
            }
        )
    selected = _u32(session, battle + 0x1C)
    return {
        "selected": (
            _s32(session, _u32(session, selected + 0x38) + 0x20)
            if selected != 0
            else -1
        ),
        "current_side": _s32(session, battle + 0x0C),
        "round": _s32(session, battle + 0x74),
        "outcome": _s32(session, battle + 0x44),
        "units": unit_records,
        "fort_strength": [
            _s32(session, battle + 0x54 + 4 * index) for index in range(8)
        ],
        "crt_rand": _crt_rand_state(
            session, records, occurrences, breakpoint_roles
        ),
    }


def _drive_interactive_battle_attack(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    hover_state: int,
) -> dict[str, object]:
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
        raise RuntimeError("fixture has no hostile army redeploy")
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
    session.assign(f"*(short*)0x{sim_mgr + 0x2E:08x}", defender)
    session.assign(f"*(short*)0x{sim_mgr + 0x48:08x}", 0)
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    _invoke_thiscall(
        session,
        _FORM_STACKS,
        army_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    session.assign(f"*(int*)0x{army_mgr + 0x10:08x}", 1)
    _invoke_thiscall(
        session,
        _RESOLVE_NEXT_MOVE,
        army_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    battle = _u32(session, army_mgr + 0x3A4)
    if battle == 0:
        raise RuntimeError("redeploy did not create a land battle")
    active_nation = _s16(session, sim_mgr + 0x2E)
    player14 = _u32(session, battle + 0x14)
    player18 = _u32(session, battle + 0x18)
    for player in (player14, player18):
        watched = (
            _eval_int(session, f"*(int*)0x{player + 0x1C:08x}")
            == active_nation
        )
        session.assign(
            f"*(char*)0x{player + 0x0E:08x}", 0 if watched else 1
        )
    snapshots: list[object] = []
    kinds: list[int] = []
    targets: list[int] = []
    actuals: list[int] = []
    if not _pump_battle_to_active_input(
        session, battle, active_nation, records, occurrences, breakpoint_roles
    ):
        raise RuntimeError("retail battle did not reach active-nation input")
    snapshots.append(
        _battle_snapshot(
            session, battle, records, occurrences, breakpoint_roles
        )
    )
    attacked = 0
    guard = 40
    tile_count = _eval_int(session, f"*(int*)0x{battle + 0x3C:08x}")
    while (
        not attacked
        and _s32(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS
        and guard > 0
    ):
        guard -= 1
        target = -1
        grid = _u32(session, battle + 0x04)
        costs = _u32(session, battle + 0x24)
        for tile in range(tile_count):
            if (
                _invoke_thiscall(
                    session,
                    _HOVER_STATE_INDEX,
                    battle,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(tile,),
                )
                == hover_state
            ):
                target = tile
                break
        if target >= 0:
            _invoke_thiscall(
                session,
                _DISPATCH_HOVER_ACTION,
                battle,
                records,
                occurrences,
                breakpoint_roles,
                args=(target,),
            )
            kinds.append(2)
            targets.append(target)
            actuals.append(-1)
            attacked = 1
        elif hover_state == 5:
            _invoke_thiscall(
                session,
                _FINISH_TACTICAL_ACTION,
                battle,
                records,
                occurrences,
                breakpoint_roles,
            )
            kinds.append(0)
            targets.append(-1)
            actuals.append(-1)
        else:
            best_distance = 9999
            moving = _u32(session, battle + 0x1C)
            for tile in range(tile_count):
                if (
                    _s16(session, costs + 2 * tile) <= 0
                    or _u32(session, grid + _TACTICAL_TILE_STRIDE * tile + 4)
                    != 0
                ):
                    continue
                distance = 9999
                for enemy_tile in range(tile_count):
                    occupant = _u32(
                        session,
                        grid + _TACTICAL_TILE_STRIDE * enemy_tile + 4,
                    )
                    if occupant == 0:
                        continue
                    if _s32(session, occupant + 0x20) != _s32(
                        session, moving + 0x20
                    ):
                        candidate = _hex_tile_distance(tile, enemy_tile)
                        if candidate < distance:
                            distance = candidate
                if distance < best_distance:
                    best_distance = distance
                    target = tile
            if target < 0:
                _invoke_thiscall(
                    session,
                    _FINISH_TACTICAL_ACTION,
                    battle,
                    records,
                    occurrences,
                    breakpoint_roles,
                )
                kinds.append(0)
                targets.append(-1)
                actuals.append(-1)
            else:
                _invoke_virtual(
                    session,
                    battle,
                    _MOVE_TACTICAL_VTABLE,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(moving, target),
                )
                kinds.append(1)
                targets.append(target)
                actuals.append(_s32(session, moving + 0x08))
        if not _pump_battle_to_active_input(
            session,
            battle,
            active_nation,
            records,
            occurrences,
            breakpoint_roles,
        ):
            raise RuntimeError(
                "retail input did not return to active nation"
            )
        snapshots.append(
            _battle_snapshot(
                session, battle, records, occurrences, breakpoint_roles
            )
        )
    if not attacked:
        raise RuntimeError("retail battle never reached the attack type")
    # AutoArmyBattleToCommit.
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
    while _s32(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS:
        if guard <= 0:
            raise RuntimeError("retail tactical auto did not terminate")
        guard -= 1
        _next_tactical_move(
            session, battle, records, occurrences, breakpoint_roles
        )
    _next_tactical_move(
        session, battle, records, occurrences, breakpoint_roles
    )
    return {
        "kinds": kinds,
        "targets": targets,
        "actuals": actuals,
        "snapshots": snapshots,
        **_capture_turn_state(session),
    }


# --- interactive_army_battle_done/_move/_retreat + auto_resolve retail drives ---
# Shared hostile-battle prologue: pinned srand, all orders cleared, one hostile
# redeploy under a forced war, FormStacks + ordinal + ResolveNextMove, then the
# active nation's side is unwatched for input. Matches the native cases exactly.

_ELIGIBLE_EVENT = 0x00581280
_VT_MOVE_ARMY = 0x15C  # slot 0x57 -> TAutoGreatPower::MoveArmy 0x4e78f0
_VT_ADVISORY_CASE16 = 0x288  # slot 0xa2 -> ...Case16 0x4e9a50
_ITEM_ORDER_SET_QUANTITY = 0x004B53D0


def _setup_hostile_battle(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    set_active: bool = True,
) -> tuple[int, int, int]:
    """Returns (sim_mgr, army_mgr, battle) with the created battle pending."""
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
    _clear_all_military_orders(
        session, records, occurrences, breakpoint_roles
    )
    snapshot = _TerrainSnapshot(session, _u32(session, _GLOBAL_MAP_STATE))
    snapshot.refresh_provinces()
    unit, dest, defender = _find_hostile_redeploy(session, snapshot)
    if unit == 0:
        raise RuntimeError("fixture has no hostile army redeploy")
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
    if set_active:
        session.assign(f"*(short*)0x{sim_mgr + 0x2E:08x}", owner)
    session.assign(f"*(short*)0x{sim_mgr + 0x48:08x}", 0)
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    _invoke_thiscall(
        session,
        _FORM_STACKS,
        army_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    session.assign(f"*(int*)0x{army_mgr + 0x10:08x}", 1)
    _invoke_thiscall(
        session,
        _RESOLVE_NEXT_MOVE,
        army_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    battle = _u32(session, army_mgr + 0x3A4)
    if battle == 0:
        raise RuntimeError("redeploy did not create a land battle")
    return sim_mgr, army_mgr, battle


def _unwatch_active_side(
    session: GdbSession, battle: int, active_nation: int
) -> tuple[int, int]:
    """Mirror StopActiveNationArmyPlayerForInput: watch only the active
    nation's side. Returns (player14, player18)."""
    player14 = _u32(session, battle + 0x14)
    player18 = _u32(session, battle + 0x18)
    for player in (player14, player18):
        watched = (
            _eval_int(session, f"*(int*)0x{player + 0x1C:08x}")
            == active_nation
        )
        session.assign(
            f"*(char*)0x{player + 0x0E:08x}", 0 if watched else 1
        )
    return player14, player18


def _auto_battle_to_commit(
    session: GdbSession,
    battle: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    """Mirror AutoArmyBattleToCommit: unwatch both sides, pulse a pending end
    of action, then run NextMove to a decision plus one extra step."""
    player14 = _u32(session, battle + 0x14)
    player18 = _u32(session, battle + 0x18)
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
    while _s32(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS:
        if guard <= 0:
            raise RuntimeError("retail tactical auto did not terminate")
        guard -= 1
        _next_tactical_move(
            session, battle, records, occurrences, breakpoint_roles
        )
    _next_tactical_move(
        session, battle, records, occurrences, breakpoint_roles
    )


def _drive_interactive_battle_done(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr, _army_mgr, battle = _setup_hostile_battle(
        session, records, occurrences, breakpoint_roles
    )
    active_nation = _s16(session, sim_mgr + 0x2E)
    _unwatch_active_side(session, battle, active_nation)
    snapshots = []
    if not _pump_battle_to_active_input(
        session, battle, active_nation, records, occurrences, breakpoint_roles
    ):
        raise RuntimeError("retail battle did not reach active-nation input")
    snapshots.append(
        _battle_snapshot(
            session, battle, records, occurrences, breakpoint_roles
        )
    )
    _invoke_thiscall(
        session,
        _FINISH_TACTICAL_ACTION,
        battle,
        records,
        occurrences,
        breakpoint_roles,
    )
    if not _pump_battle_to_active_input(
        session, battle, active_nation, records, occurrences, breakpoint_roles
    ):
        raise RuntimeError(
            "retail Done did not reach the next active-nation input"
        )
    snapshots.append(
        _battle_snapshot(
            session, battle, records, occurrences, breakpoint_roles
        )
    )
    _auto_battle_to_commit(
        session, battle, records, occurrences, breakpoint_roles
    )
    return {"snapshots": snapshots, **_capture_turn_state(session)}


def _drive_interactive_battle_move(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr, _army_mgr, battle = _setup_hostile_battle(
        session, records, occurrences, breakpoint_roles
    )
    active_nation = _s16(session, sim_mgr + 0x2E)
    _unwatch_active_side(session, battle, active_nation)
    snapshots = []
    targets: list[int] = []
    actuals: list[int] = []
    if not _pump_battle_to_active_input(
        session, battle, active_nation, records, occurrences, breakpoint_roles
    ):
        raise RuntimeError("retail battle did not reach active-nation input")
    snapshots.append(
        _battle_snapshot(
            session, battle, records, occurrences, breakpoint_roles
        )
    )
    tile_count = _s32(session, battle + 0x3C)
    grid = _u32(session, battle + 0x04)
    costs = _u32(session, battle + 0x24)
    reaction_stopped = 0
    input_guard = 20
    while (
        not reaction_stopped
        and _s32(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS
        and input_guard > 0
    ):
        input_guard -= 1
        target = -1
        best_distance = 9999
        moving = _u32(session, battle + 0x1C)
        for tile in range(tile_count):
            if (
                _s16(session, costs + 2 * tile) <= 0
                or _u32(session, grid + _TACTICAL_TILE_STRIDE * tile + 4)
                != 0
            ):
                continue
            distance = 9999
            for enemy_tile in range(tile_count):
                occupant = _u32(
                    session,
                    grid + _TACTICAL_TILE_STRIDE * enemy_tile + 4,
                )
                if occupant == 0:
                    continue
                if _s32(session, occupant + 0x20) != _s32(
                    session, moving + 0x20
                ):
                    candidate = _hex_tile_distance(tile, enemy_tile)
                    if candidate < distance:
                        distance = candidate
            if distance < best_distance:
                best_distance = distance
                target = tile
        if target < 0:
            raise RuntimeError(
                "selected tactical unit reached no reaction-fire move target"
            )
        _invoke_virtual(
            session,
            battle,
            _MOVE_TACTICAL_VTABLE,
            records,
            occurrences,
            breakpoint_roles,
            args=(moving, target),
        )
        targets.append(target)
        actuals.append(_s32(session, moving + 0x08))
        reaction_stopped = 1 if _s32(session, moving + 0x08) != target else 0
        if not _pump_battle_to_active_input(
            session,
            battle,
            active_nation,
            records,
            occurrences,
            breakpoint_roles,
        ):
            raise RuntimeError(
                "retail Move did not reach the next active-nation input"
            )
        snapshots.append(
            _battle_snapshot(
                session, battle, records, occurrences, breakpoint_roles
            )
        )
    if not reaction_stopped:
        raise RuntimeError(
            "retail fixture did not produce reaction-stopped movement"
        )
    _auto_battle_to_commit(
        session, battle, records, occurrences, breakpoint_roles
    )
    return {
        "targets": targets,
        "actuals": actuals,
        "snapshots": snapshots,
        **_capture_turn_state(session),
    }


def _drive_interactive_battle_retreat(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr, _army_mgr, battle = _setup_hostile_battle(
        session, records, occurrences, breakpoint_roles
    )
    active_nation = _s16(session, sim_mgr + 0x2E)
    _unwatch_active_side(session, battle, active_nation)
    if not _pump_battle_to_active_input(
        session, battle, active_nation, records, occurrences, breakpoint_roles
    ):
        raise RuntimeError("retail battle did not reach active-nation input")
    initial = _battle_snapshot(
        session, battle, records, occurrences, breakpoint_roles
    )
    player14 = _u32(session, battle + 0x14)
    player18 = _u32(session, battle + 0x18)
    side = _s32(session, battle + 0x0C)
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
    _auto_battle_to_commit(
        session, battle, records, occurrences, breakpoint_roles
    )
    return {"snapshots": [initial], **_capture_turn_state(session)}


def _drive_auto_resolve_land_battle(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    _sim_mgr, _army_mgr, battle = _setup_hostile_battle(
        session,
        records,
        occurrences,
        breakpoint_roles,
        set_active=False,
    )
    guard = 20000
    while _s32(session, battle + 0x44) == _TACTICAL_BATTLE_IN_PROGRESS:
        if guard <= 0:
            raise RuntimeError("retail tactical auto did not terminate")
        guard -= 1
        _next_tactical_move(
            session, battle, records, occurrences, breakpoint_roles
        )
    _next_tactical_move(
        session, battle, records, occurrences, breakpoint_roles
    )
    return _capture_military_phase(session)


# --- army_movement_give_orders / advisory_map_missions_case16 ------------------
# Both loop the great-power slots, keep TAutoGreatPower instances eligible via
# TSimMgr::IsNationSlotEligibleForEventProcessing (0x581280), then dispatch the
# minister entry point through the nation vtable (MoveArmy byte 0x15c, case-16
# advisory queueing byte 0x288).


def _auto_great_power_slots(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> list[tuple[int, int]]:
    sim_mgr = _u32(session, _SIM_MGR)
    slots = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        if (
            _runtime_class(
                session, nation, records, occurrences, breakpoint_roles
            )
            != _CLASS_AUTO_GREAT_POWER
        ):
            continue
        eligible = (
            _invoke_thiscall(
                session,
                _ELIGIBLE_EVENT,
                sim_mgr,
                records,
                occurrences,
                breakpoint_roles,
                args=(slot,),
            )
            & 0xFF
        )
        if eligible == 0:
            continue
        slots.append((slot, nation))
    return slots


def _drive_advisory_case16(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    slots = _auto_great_power_slots(
        session, records, occurrences, breakpoint_roles
    )
    if not slots:
        raise RuntimeError("the retail fixture has no AutoGreatPower")
    for _slot, nation in slots:
        _invoke_virtual(
            session,
            nation,
            _VT_ADVISORY_CASE16,
            records,
            occurrences,
            breakpoint_roles,
        )
    return _capture_missions(
        session, records, occurrences, breakpoint_roles
    )


def _drive_army_movement(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    slots = _auto_great_power_slots(
        session, records, occurrences, breakpoint_roles
    )
    if not slots:
        raise RuntimeError("the retail fixture has no AutoGreatPower")
    for _slot, nation in slots:
        _invoke_virtual(
            session,
            nation,
            _VT_MOVE_ARMY,
            records,
            occurrences,
            breakpoint_roles,
        )
    return _capture_military_phase(session)


# --- city_item_order_increase / _decrease --------------------------------------
# Seed the city's fabric stock + clothing production slots, then drive the
# clothing TItemOrder's SetQuantity (0x4b53d0). The decrease case pre-seeds
# quantity 1 before the transition boundary.

_CITY_ORDER_SLOTS = 0xE4
_CITY_STOCKS = 0xB6
_CITY_PRODUCTION_ORDER_TABLE = 0x1DC
_CITY_PRODUCTION_ACCUM = 0x1FC
_ORDER_QUANTITY = 0x04
_ORDER_REQUESTED = 0x4C
_ORDER_TRACKING_SLOTS = 0x10
_RESOURCE_FABRIC = 8
_RESOURCE_CLOTHING = 13


def _drive_city_item_order(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    quantity: int,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    nation = _nation_pointer(session, _s16(session, sim_mgr + 0x2E))
    if nation == 0:
        raise RuntimeError("retail loaded player has no active nation")
    city = _u32(session, nation + 0x894)
    order = _u32(
        session, city + _CITY_ORDER_SLOTS + _RESOURCE_CLOTHING * 4
    )
    if order == 0:
        raise RuntimeError("retail city has no clothing order slot")
    session.assign(
        f"*(short*)0x{city + _CITY_STOCKS + _RESOURCE_FABRIC * 2:08x}", 2
    )
    session.assign(
        f"*(short*)0x{city + _CITY_PRODUCTION_ORDER_TABLE + 2:08x}", 1
    )
    session.assign(
        f"*(short*)0x{city + _CITY_PRODUCTION_ACCUM + 2:08x}", 1
    )
    if quantity == 0:
        _invoke_thiscall(
            session,
            _ITEM_ORDER_SET_QUANTITY,
            order,
            records,
            occurrences,
            breakpoint_roles,
            args=(1,),
        )
    applied = (
        _invoke_thiscall(
            session,
            _ITEM_ORDER_SET_QUANTITY,
            order,
            records,
            occurrences,
            breakpoint_roles,
            args=(quantity,),
        )
        & 0xFF
    )
    result = _capture_civilians_phase(session)
    result["applied"] = applied
    result["quantity"] = _s16(session, order + _ORDER_QUANTITY)
    result["requested"] = _s16(session, order + _ORDER_REQUESTED)
    result["fabric_tracking"] = _s16(
        session, order + _ORDER_TRACKING_SLOTS + _RESOURCE_FABRIC * 2
    )
    return result


# --- opening / newspaper retail drives -----------------------------------------
# Mirrors the NativeTurnTailCases/NativeNewsCases bodies against the live retail
# process: opening civilian grant + home-city setup, the pending-action sweep,
# and the NEWS.TAB newspaper construction/turn-stop paths.

_NEWS_MGR = 0x006A43E8
_MULTIPLAYER_SETUP_FLAG = 0x006A43F0
_FIND_REACHABLE_RECRUIT_TILE = 0x00514C80
_SET_HOME_CITY = 0x004DFD30
_NEWS_ADD_MISC_EVENT = 0x0055CD00
_NEWS_START_PHASE = 0x0055B8E0
_VT_LIST_RESET_HOOK = 0x08 * 4
_VT_MARK_PENDING_HANDLED = 0x2C * 4
_VT_IS_REMOTE = 0x28 * 4

_NEWS_EVENT_KIND_NAMES = {
    0x00: "war_declared_by_subject",
    0x01: "war_declared_against_subject",
    0x02: "peace_treaty_accepted",
    0x03: "join_empire_accepted",
    0x04: "alliance_accepted",
    0x05: "non_aggression_pact_accepted",
    0x07: "peace_treaty_rejected",
    0x09: "join_empire_rejected",
    0x0B: "alliance_rejected",
    0x0D: "non_aggression_pact_rejected",
    0x12: "trade_consulate_established",
    0x14: "embassy_established",
    0x16: "minor_empire_affiliation_changed",
    0x17: "minor_territory_relationship_affected",
    0x18: "peace_relationship_propagated",
    0x19: "war_with_independent_minor",
    0x1A: "alliance_relationship_established",
    0x1B: "nation_joined_empire",
    0x1C: "nation_joined_war",
    0x1D: "nation_transferred",
}

_NEWS_RESOURCE_NAMES = (
    "cotton", "wool", "timber", "coal", "iron", "horses", "oil", "food",
    "fabric", "lumber", "paper", "steel", "fuel", "clothing", "furniture",
    "hardware", "arms", "grain", "fruit", "fish", "livestock", "gems", "gold",
)

_NEWS_TEMPLATE_COUNT = 360


def _news_nation_mask(source: int) -> list[bool]:
    if source & ~((1 << _NATION_SLOT_COUNT) - 1):
        raise RuntimeError(
            "shared newspaper event mask contains bits outside the nation table"
        )
    return [
        (source & (1 << nation)) != 0 for nation in range(_NATION_SLOT_COUNT)
    ]


def _news_argument(kind: int, value: int) -> dict[str, object]:
    if kind == 0:
        return {"kind": "empty"}
    if kind in (1, 2):
        return {
            "kind": "nation_mask" if kind == 1 else "nation_list",
            "nations": _news_nation_mask(value),
        }
    if kind == 3:
        return {"kind": "province", "province": value}
    if kind == 4:
        return {"kind": "zone", "ordinal": value}
    raise RuntimeError(f"newspaper argument has an unknown kind {kind}")


def _capture_news(session: GdbSession) -> dict[str, object]:
    """Mirror CaptureNews/CapturePendingNewspaperEvents on the retail process."""
    news_mgr = _u32(session, _NEWS_MGR)
    if news_mgr == 0:
        raise RuntimeError("retail news manager is unavailable")
    template_count = _eval_int(
        session, f"*(int*)0x{news_mgr + 0x08:08x}"
    )
    if template_count == 0:
        news: dict[str, object] = {
            "pages": [None] * _MAJOR_NATION_COUNT,
            "last_used_turn_by_nation_and_template": [
                [0] * _NEWS_TEMPLATE_COUNT for _ in range(_MAJOR_NATION_COUNT)
            ],
        }
    else:
        if template_count != _NEWS_TEMPLATE_COUNT:
            raise RuntimeError(
                "initialized newspaper state does not use the 360-row NEWS.TAB"
            )
        template_table = _u32(session, news_mgr + 0x04)
        templates = session.read_memory(
            template_table, _NEWS_TEMPLATE_COUNT * 0x18
        )
        pages: list[object] = []
        last_used_by_nation: list[object] = []
        for nation in range(_MAJOR_NATION_COUNT):
            tick_ptr = _u32(session, news_mgr + 0xEF4 + nation * 4)
            if tick_ptr == 0:
                raise RuntimeError(
                    "initialized newspaper state has no last-used history"
                )
            block = session.read_memory(
                news_mgr + 0x0C + nation * 9 * 0x3C, 9 * 0x3C
            )
            stories_raw = [
                block[index * 0x3C : (index + 1) * 0x3C] for index in range(9)
            ]
            if not any(
                struct.unpack("<i", story[0x20:0x24])[0] != 0
                for story in stories_raw
            ):
                pages.append(None)
            else:
                columns = []
                for column in range(3):
                    rows = []
                    for row in range(3):
                        story = stories_raw[column * 3 + row]
                        entry = story[0x20:0x38]
                        if struct.unpack("<i", entry[:4])[0] == 0:
                            rows.append(None)
                            continue
                        template_index = -1
                        for index in range(_NEWS_TEMPLATE_COUNT):
                            if entry == templates[index * 0x18 : (index + 1) * 0x18]:
                                if template_index != -1:
                                    raise RuntimeError(
                                        "newspaper story matches more than one"
                                        " template row"
                                    )
                                template_index = index
                        if template_index == -1:
                            raise RuntimeError(
                                "newspaper story does not match NEWS.TAB"
                            )
                        kinds = struct.unpack("<4i", story[0x10:0x20])
                        values = struct.unpack("<4i", story[0x00:0x10])
                        rows.append(
                            {
                                "template_index": template_index,
                                "story_id": struct.unpack("<i", entry[:4])[0],
                                "feature": story[0x38] != 0,
                                "arguments": [
                                    _news_argument(kinds[i], values[i])
                                    for i in range(4)
                                ],
                            }
                        )
                    columns.append(rows)
                pages.append({"stories": columns})
            last_used_by_nation.append(
                list(
                    struct.unpack(
                        f"<{_NEWS_TEMPLATE_COUNT}h",
                        session.read_memory(tick_ptr, _NEWS_TEMPLATE_COUNT * 2),
                    )
                )
            )
        news = {
            "pages": pages,
            "last_used_turn_by_nation_and_template": last_used_by_nation,
        }

    queue = _u32(session, news_mgr + 0xEF0)
    if queue == 0:
        raise RuntimeError("shared newspaper event queue is unavailable")
    record_size = _eval_int(
        session, f"*(short*)0x{queue + 0x14:08x}"
    )
    if record_size != 0x10:
        raise RuntimeError("shared newspaper event queue has the wrong record size")
    count = _eval_int(session, f"*(int*)0x{queue + 8:08x}")
    data = _u32(session, queue + 4)
    events: list[dict[str, object]] = []
    if count > 0 and data != 0:
        pointers = struct.unpack(
            f"<{count}I", session.read_memory(data, 4 * count)
        )
        for pointer in pointers:
            if pointer == 0:
                raise RuntimeError(
                    "shared newspaper event queue contains a null record"
                )
            kind, subject, mask, related = struct.unpack(
                "<4i", session.read_memory(pointer, 0x10)
            )
            if kind == 0x0F:
                if related < 0 or related >= len(_NEWS_RESOURCE_NAMES):
                    raise RuntimeError(
                        "shared newspaper shortage has an invalid resource"
                    )
                events.append(
                    {
                        "kind": "shortage",
                        "subject": subject,
                        "affected_nations": _news_nation_mask(mask),
                        "resource": _NEWS_RESOURCE_NAMES[related],
                    }
                )
            elif kind == 0x11:
                events.append(
                    {
                        "kind": "miscellaneous",
                        "audience": None if subject == 999 else subject,
                        "story_code": mask,
                    }
                )
            else:
                if kind not in _NEWS_EVENT_KIND_NAMES:
                    raise RuntimeError(
                        "shared newspaper queue contains an unknown"
                        " inter-nation event kind"
                    )
                events.append(
                    {
                        "kind": "inter_nation",
                        "event": _NEWS_EVENT_KIND_NAMES[kind],
                        "subject": subject,
                        "related_nations": _news_nation_mask(mask),
                    }
                )
    return {"news": news, "newspaper_events": events}


def _news_capture_fields(session: GdbSession) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    fields = _capture_news(session)
    fields["turn_phase"] = _eval_int(
        session, f"*(int*)0x{sim_mgr + 4:08x}"
    )
    fields["active_nation"] = _s16(session, sim_mgr + 0x2E)
    fields["economic_turn"] = _s16(session, sim_mgr + 0x2C)
    fields["turn_flow_status_flags"] = _eval_int(
        session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
    )
    return fields


def _drive_construct_newspaper(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    queue_misc_event: bool,
) -> dict[str, object]:
    """Mirror RunNewspaperConstruction: reset the shared event queue, optionally
    queue a miscellaneous event, then run TNewsMgr::StartNewsPhase."""
    news_mgr = _u32(session, _NEWS_MGR)
    queue = _u32(session, news_mgr + 0xEF0)
    if news_mgr == 0 or queue == 0:
        raise RuntimeError("newspaper state is unavailable")
    _invoke_virtual(
        session, queue, _VT_LIST_RESET_HOOK, records, occurrences,
        breakpoint_roles,
    )
    if queue_misc_event:
        _invoke_thiscall(
            session, _NEWS_ADD_MISC_EVENT, news_mgr, records, occurrences,
            breakpoint_roles, args=(999, 3, 1),
        )
    # Match the srand(0x1234) in RunNewspaperConstruction so the filler-story
    # rand() draws line up between retail and recomp.
    _invoke_thiscall(
        session, _SRAND, 0, records, occurrences, breakpoint_roles,
        args=(0x1234,),
    )
    _invoke_thiscall(
        session, _NEWS_START_PHASE, news_mgr, records, occurrences,
        breakpoint_roles,
    )
    return _news_capture_fields(session)


def _drive_turn_stop_newspaper(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    session.assign(f"*(int*)0x{sim_mgr + 0x04:08x}", 0x0F)
    # Match the srand(0x1234) in RunNewspaperTurnStop so the news phase's
    # filler-story rand() draws line up between retail and recomp.
    _invoke_thiscall(
        session, _SRAND, 0, records, occurrences, breakpoint_roles,
        args=(0x1234,),
    )
    _invoke_thiscall(
        session, _ADVANCE_TURN_STATE, sim_mgr, records, occurrences,
        breakpoint_roles,
    )
    result = _news_capture_fields(session)
    result.update(_capture_pending_status(session))
    result["dispatched_event"] = _current_turn_event(session)
    result["rng"] = _capture_rng_state(
        session, records, occurrences, breakpoint_roles
    )
    return result


def _capture_pending_status(session: GdbSession) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        nations.append(
            {
                "pending_actions": [
                    byte - 0x100 if byte & 0x80 else byte
                    for byte in session.read_memory(nation + 0x8C8, 0x0D)
                ],
                "pending_payloads": list(
                    struct.unpack(
                        "<13h", session.read_memory(nation + 0x8D6, 26)
                    )
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
        "pending_nations": nations,
    }


def _drive_pending_status(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    navy_growth_only: bool,
) -> dict[str, object]:
    """Mirror RunNewspaperPendingStatus/RunNewspaperNavyGrowthRewardLevels."""
    sim_mgr = _u32(session, _SIM_MGR)
    active_slot = _s16(session, sim_mgr + 0x2E)
    if navy_growth_only:
        nation = _nation_pointer(session, active_slot)
        if nation == 0:
            raise RuntimeError("retail loaded game has no active nation")
        session.assign(f"*(signed char*)0x{nation + 0x8C8:08x}", 0x32)
        session.assign(f"*(short*)0x{nation + 0x8D6:08x}", 1)
    else:
        for slot in range(_MAJOR_NATION_COUNT):
            eligible = (
                _invoke_thiscall(
                    session,
                    _FN_IS_ELIGIBLE_FOR_EVENTS,
                    sim_mgr,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(slot,),
                )
                & 0xFF
            )
            if not eligible:
                continue
            nation = _nation_pointer(session, slot)
            if nation == 0:
                continue
            for index, payload in ((0, 3), (1, 6), (3, -1)):
                session.assign(
                    f"*(signed char*)0x{nation + 0x8C8 + index:08x}", 0x32
                )
                session.assign(
                    f"*(short*)0x{nation + 0x8D6 + 2 * index:08x}", payload
                )
    for slot in range(_MAJOR_NATION_COUNT):
        eligible = (
            _invoke_thiscall(
                session,
                _FN_IS_ELIGIBLE_FOR_EVENTS,
                sim_mgr,
                records,
                occurrences,
                breakpoint_roles,
                args=(slot,),
            )
            & 0xFF
        )
        if not eligible:
            continue
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        _invoke_virtual(
            session, nation, _VT_MARK_PENDING_HANDLED, records, occurrences,
            breakpoint_roles,
        )
    return _capture_pending_status(session)


def _drive_opening_civilian_grant(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunOpeningCivilianGrant: seed difficulty/scenario/eligibility,
    then spawn prospector+engineer plus the three difficulty-0 grant units."""
    sim_mgr = _u32(session, _SIM_MGR)
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    active_slot = _s16(session, sim_mgr + 0x2E)
    nation = _nation_pointer(session, active_slot)
    city = _u32(session, nation + 0x894) if nation else 0
    if nation == 0 or city == 0 or map_state == 0:
        raise RuntimeError("opening civilian grant state is unavailable")
    session.assign(f"*(int*)0x{sim_mgr + 0x40:08x}", 0)
    session.assign(f"*(short*)0x{sim_mgr + 0x114:08x}", 0)
    session.assign(f"*(signed char*)0x{nation + 0xA0:08x}", 1)
    home_tile = _s16(session, nation + 0x88)
    nation_slot = _s16(session, nation + 0x0C)

    def spawn(kind: int, allow_flag: int) -> None:
        tile = _invoke_thiscall(
            session,
            _FIND_REACHABLE_RECRUIT_TILE,
            map_state,
            records,
            occurrences,
            breakpoint_roles,
            args=(home_tile, allow_flag),
        ) & 0xFFFF
        tile = tile - 0x10000 if tile & 0x8000 else tile
        _new_civilian_unit(
            session, kind, tile, nation_slot, records, occurrences,
            breakpoint_roles,
        )

    spawn(1, 0)
    spawn(4, 1)
    order_count_addr = city + 0x5C + 2
    session.assign(
        f"*(short*)0x{order_count_addr:08x}",
        _s16(session, order_count_addr) + 2,
    )
    if _u8(session, nation + 0xA0):
        session.assign(
            f"*(short*)0x{order_count_addr:08x}",
            _s16(session, order_count_addr) + 6,
        )
        spawn(1, 0)
        spawn(0, 0)
        spawn(2, 0)
    return _capture_civilians_phase(session)


def _drive_opening_home_city_setup(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> dict[str, object]:
    """Mirror RunOpeningHomeCitySetup: SetHomeCityTileAndDisplayName(-1, 0) on
    every non-remote major nation while the multiplayer-setup gate is clear."""
    session.assign(
        f"*(signed char*)0x{_MULTIPLAYER_SETUP_FLAG:08x}", 0
    )
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        remote = (
            _invoke_virtual(
                session, nation, _VT_IS_REMOTE, records, occurrences,
                breakpoint_roles,
            )
            & 0xFF
        )
        if remote or _u8(session, _MULTIPLAYER_SETUP_FLAG):
            continue
        _invoke_thiscall(
            session, _SET_HOME_CITY, nation, records, occurrences,
            breakpoint_roles, args=(-1, 0),
        )
    return _capture_civilians_phase(session)


# --- army map-selection retail drives -------------------------------------------
# Mirror the NativeArmyOrderCases bodies against the live retail process: the
# TArmyMgr/g_pMapContextActionManager selection and order-mode surface
# (pendingMapActionIndex +0x31c), the toolbar category tally, and the map-click
# cursor/order validators.

_ARMY_SELECT_CATEGORY = 0x004A43F0
_ARMY_SELECT_PROVINCE = 0x004A45E0
_ARMY_NEXT_PROVINCE = 0x004A4760
_CIVILIAN_CURSOR_STATE = 0x004A4C80
_VALIDATE_ORDER_TILE = 0x004A5080
_UBER_SET_MAP_MODE = 0x00596CB0
_MIL_CAN_UPGRADE = 0x005C3650
_UNIT_CATEGORY_TABLE = 0x00695528
_VIEW_MGR = 0x006A21BC
# TUnit.h "slot" comments are byte offsets; TArmyMgr.h "slot" comments are indices.
_VT_SELECT_MOVABLE = 0x14 * 4
_VT_SET_ORDERS_IDLE = 0x16 * 4
_VT_UNIT_MOVE_TO = 0x28
_VT_UNIT_SET_ORDERS = 0x34
_MIL_KIND_MINUTEMEN = 0
_MIL_KIND_REGULARS = 2
_DIPLO_REL_WAR = 6


def _province_record(session: GdbSession, province: int) -> int:
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    return _u32(session, map_state + 0x10) + province * _PROVINCE_STRIDE


def _army_active_nation(session: GdbSession) -> tuple[int, int]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_slot = _s16(session, sim_mgr + 0x2E)
    return _nation_pointer(session, active_slot), active_slot


def _army_first_owned_province(session: GdbSession, nation: int) -> int:
    owned = _u32(session, nation + 0x90)
    if nation == 0 or owned == 0:
        return -1
    entries = _longint_list_entries(session, owned)
    return entries[0] if entries else -1


def _adjacent_owned_province(session: GdbSession, province: int) -> int:
    record = _province_record(session, province)
    owner = _s8(session, record)
    count = _s8(session, record + 0x08)
    for index in range(count):
        dest = _s16(session, record + 0x0A + 2 * index)
        if 0 <= dest < _PROVINCE_COUNT:
            if _s8(session, _province_record(session, dest)) == owner:
                return dest
    return -1


def _adjacent_foreign_province(session: GdbSession, province: int) -> int:
    record = _province_record(session, province)
    owner = _s8(session, record)
    count = _s8(session, record + 0x08)
    for index in range(count):
        dest = _s16(session, record + 0x0A + 2 * index)
        if 0 <= dest < _PROVINCE_COUNT:
            dest_owner = _s8(session, _province_record(session, dest))
            if dest_owner != owner and dest_owner != -1:
                return dest
    return -1


def _find_owned_foreign_pair(session: GdbSession, active_slot: int) -> tuple[int, int]:
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    base = _u32(session, map_state + 0x10)
    total = _PROVINCE_COUNT * _PROVINCE_STRIDE
    owners = b""
    for offset in range(0, total, 0x2000):
        owners += session.read_memory(base + offset, min(0x2000, total - offset))
    for province in range(_PROVINCE_COUNT):
        if struct.unpack(
            "<b", owners[province * _PROVINCE_STRIDE :][:1]
        )[0] != active_slot:
            continue
        adjacent = _adjacent_foreign_province(session, province)
        if adjacent >= 0:
            return province, adjacent
    return -1, -1


def _empty_tile_index(session: GdbSession) -> int:
    map_state = _u32(session, _GLOBAL_MAP_STATE)
    terrain_base = _u32(session, map_state + 0x0C)
    total = _TILE_COUNT * _TERRAIN_RECORD_STRIDE
    tiles = b""
    for offset in range(0, total, 0x2000):
        tiles += session.read_memory(
            terrain_base + offset, min(0x2000, total - offset)
        )
    for tile in range(_TILE_COUNT):
        if struct.unpack(
            "<h", tiles[tile * _TERRAIN_RECORD_STRIDE + 0x14 :][:2]
        )[0] == -1:
            return tile
    return -1


def _spawn_stationed(
    session: GdbSession,
    kind: int,
    province: int,
    nation_slot: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> int:
    unit = _new_military_unit(
        session, kind, -1, nation_slot, records, occurrences,
        breakpoint_roles,
    )
    _invoke_virtual(
        session, unit, _VT_UNIT_MOVE_TO, records, occurrences,
        breakpoint_roles, args=(province,),
    )
    _invoke_virtual(
        session, unit, _VT_UNIT_SET_ORDERS, records, occurrences,
        breakpoint_roles, args=(0, -1),
    )
    return unit


def _set_unit_orders(
    session: GdbSession,
    unit: int,
    order: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    _invoke_virtual(
        session, unit, _VT_UNIT_SET_ORDERS, records, occurrences,
        breakpoint_roles, args=(order, -1),
    )


def _stationed_chain(session: GdbSession, province: int) -> list[int]:
    units = []
    unit = _u32(session, _province_record(session, province) + 0x98)
    while unit != 0:
        units.append(unit)
        unit = _u32(session, unit + 0x14)
    return units


def _army_ui_result(
    session: GdbSession, extra: dict[str, object] | None = None
) -> dict[str, object]:
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    payload: dict[str, object] = {
        "pending_index": _s16(session, army_mgr + 0x31C)
    }
    if extra:
        payload.update(extra)
    fields = _capture_military_phase(session)
    fields["result"] = payload
    return fields


def _drive_army_ui(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    name: str,
) -> dict[str, object]:
    nation, active_slot = _army_active_nation(session)
    army_mgr = _u32(session, _MAP_ACTION_CONTEXT_MANAGER)
    if nation == 0 or army_mgr == 0:
        raise RuntimeError("army selection state is unavailable")

    def spawn(kind: int, province: int) -> int:
        return _spawn_stationed(
            session, kind, province, active_slot, records, occurrences,
            breakpoint_roles,
        )

    province = _army_first_owned_province(session, nation)
    if name in (
        "army_toolbar_counts",
        "army_select_category",
        "army_set_order_mode",
        "army_select_province",
        "army_click_blocked",
        "army_click_friendly",
        "army_selection_cycling",
    ) and province < 0:
        raise RuntimeError("the fixture has no owned province")

    if name == "army_toolbar_counts":
        spawn(_MIL_KIND_REGULARS, province)
        sleeping = spawn(_MIL_KIND_REGULARS, province)
        spawn(_MIL_KIND_MINUTEMEN, province)
        _set_unit_orders(
            session, sleeping, 2, records, occurrences, breakpoint_roles
        )
        available = [0] * 10
        totals = [0] * 10
        can_upgrade = False
        categories = struct.unpack(
            "<64h", session.read_memory(_UNIT_CATEGORY_TABLE, 128)
        )
        for unit in _stationed_chain(session, province):
            raw = session.read_memory(unit, 0x40)
            order = struct.unpack("<h", raw[0x08:0x0A])[0]
            category = categories[struct.unpack("<h", raw[0x04:0x06])[0]]
            if order == 0:
                available[category] += 1
            if order in (0, 2, 3, 4):
                totals[category] += 1
            if (
                _invoke_thiscall(
                    session, _MIL_CAN_UPGRADE, unit, records, occurrences,
                    breakpoint_roles,
                )
                & 0xFF
            ):
                can_upgrade = True
        return _army_ui_result(
            session,
            {
                "available": available,
                "totals": totals,
                "can_upgrade": can_upgrade,
            },
        )

    if name == "army_select_category":
        spawn(_MIL_KIND_REGULARS, province)
        spawn(_MIL_KIND_REGULARS, province)
        remaining = _invoke_thiscall(
            session, _ARMY_SELECT_CATEGORY, army_mgr, records, occurrences,
            breakpoint_roles, args=(2, province),
        ) & 0xFFFF
        if remaining & 0x8000:
            remaining -= 0x10000
        return _army_ui_result(session, {"remaining": remaining})

    if name == "army_set_order_mode":
        spawn(_MIL_KIND_REGULARS, province)
        spawn(_MIL_KIND_REGULARS, province)
        session.assign(f"*(short*)0x{army_mgr + 0x31C:08x}", province)
        _invoke_virtual(
            session, army_mgr, _VT_SET_ORDERS_IDLE, records, occurrences,
            breakpoint_roles, args=(3,),
        )
        return _army_ui_result(session)

    if name == "army_select_province":
        latr = spawn(_MIL_KIND_REGULARS, province)
        done = spawn(_MIL_KIND_REGULARS, province)
        militia = spawn(_MIL_KIND_MINUTEMEN, province)
        _set_unit_orders(
            session, latr, 3, records, occurrences, breakpoint_roles
        )
        _set_unit_orders(
            session, done, 4, records, occurrences, breakpoint_roles
        )
        _set_unit_orders(
            session, militia, 4, records, occurrences, breakpoint_roles
        )
        uber = _u32(session, _u32(session, _VIEW_MGR) + 0xF0)
        if uber == 0:
            raise RuntimeError("map uber picture is unavailable")
        _invoke_thiscall(
            session, _UBER_SET_MAP_MODE, uber, records, occurrences,
            breakpoint_roles, args=(1,),
        )
        _invoke_thiscall(
            session, _ARMY_SELECT_PROVINCE, army_mgr, records, occurrences,
            breakpoint_roles, args=(province,),
        )
        return _army_ui_result(session)

    if name == "army_click_blocked":
        tile = _empty_tile_index(session)
        if tile < 0:
            raise RuntimeError("the fixture has no empty tile")
        spawn(_MIL_KIND_REGULARS, province)
        session.assign(f"*(short*)0x{army_mgr + 0x31C:08x}", province)
        cursor = _invoke_thiscall(
            session, _CIVILIAN_CURSOR_STATE, army_mgr, records, occurrences,
            breakpoint_roles, args=(tile, 0),
        )
        return _army_ui_result(session, {"cursor": cursor})

    if name == "army_click_friendly":
        dest = _adjacent_owned_province(session, province)
        if dest < 0:
            raise RuntimeError("the fixture has no adjacent owned province")
        spawn(_MIL_KIND_REGULARS, province)
        spawn(_MIL_KIND_MINUTEMEN, province)
        session.assign(f"*(short*)0x{army_mgr + 0x31C:08x}", province)
        _invoke_virtual(
            session, army_mgr, _VT_SELECT_MOVABLE, records, occurrences,
            breakpoint_roles, args=(dest,),
        )
        return _army_ui_result(session)

    if name == "army_click_hostile":
        province, dest = _find_owned_foreign_pair(session, active_slot)
        if province < 0:
            raise RuntimeError("the fixture has no adjacent foreign province")
        spawn(_MIL_KIND_REGULARS, province)
        session.assign(f"*(short*)0x{army_mgr + 0x31C:08x}", province)
        diplo_mgr = _u32(session, _DIPLOMACY_MGR)
        dest_owner = _s8(session, _province_record(session, dest))
        matrix = diplo_mgr + _DIPLO_REL_PROPAGATION
        session.assign(
            f"*(short*)0x{matrix + 2 * (active_slot * _NATION_SLOT_COUNT + dest_owner):08x}",
            _DIPLO_REL_WAR,
        )
        session.assign(
            f"*(short*)0x{matrix + 2 * (dest_owner * _NATION_SLOT_COUNT + active_slot):08x}",
            _DIPLO_REL_WAR,
        )
        map_state = _u32(session, _GLOBAL_MAP_STATE)
        view_origin = _s16(session, map_state + 0x06)
        _invoke_thiscall(
            session, _VALIDATE_ORDER_TILE, army_mgr, records, occurrences,
            breakpoint_roles, args=(dest,),
        )
        session.assign(f"*(short*)0x{map_state + 0x06:08x}", view_origin)
        return _army_ui_result(session)

    if name == "army_selection_cycling":
        spawn(_MIL_KIND_REGULARS, province)
        session.assign(f"*(short*)0x{army_mgr + 0x31C:08x}", province)
        _invoke_virtual(
            session, army_mgr, _VT_SET_ORDERS_IDLE, records, occurrences,
            breakpoint_roles, args=(2,),
        )
        next_province = _invoke_thiscall(
            session, _ARMY_NEXT_PROVINCE, army_mgr, records, occurrences,
            breakpoint_roles, args=(active_slot,),
        ) & 0xFFFF
        if next_province & 0x8000:
            next_province -= 0x10000
        return _army_ui_result(session, {"next": next_province})

    raise RuntimeError(f"unknown army ui drive {name!r}")


# --- navy_* UI interaction retail drives --------------------------------------
# Mirrors NativeNavyOrderCases.cpp: the TOcean port-zone lookup, TZone's
# task-force factory and context-display gate, and the TTaskForce order/selection
# surface (SubmitOrders, CancelOrders, Select, SetAggression, IsValidTarget,
# GetSelected).

_OCEAN_MGR = 0x006A3FBC
_OCEAN_FIND_PORT_ZONE = 0x00563540
_ZONE_CREATE_TASK_FORCE = 0x005609E0
_ZONE_CAN_DISPLAY = 0x00560B00
_TF_SUBMIT_ORDERS = 0x005540B0
_TF_CANCEL_ORDERS = 0x005547D0
_TF_SET_AGGRESSION = 0x00552F60
_TF_SELECT_SLOT = 0x00554930
_TF_GET_SELECTED = 0x00554A30
_TF_VALID_TARGET_ZONE = 0x005544A0
_TF_VALID_TARGET_PROVINCE = 0x00554590


def _zone_ordinal(session: GdbSession, zone: int) -> int:
    return _s16(session, zone + 0x14) if zone != 0 else -1


def _navy_ui_result(
    session: GdbSession, extra: object = None
) -> dict[str, object]:
    fields = _capture_military_phase(session)
    fields["result"] = extra
    return fields


def _drive_navy_ui(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    name: str,
) -> dict[str, object]:
    sim_mgr = _u32(session, _SIM_MGR)
    active_slot = _s16(session, sim_mgr + 0x2E)

    def spawn(ship_type: int, zone: int, label: str) -> int:
        return _new_ship(
            session, ship_type, zone, active_slot, label, records,
            occurrences, breakpoint_roles,
        )

    zone = 0
    force = 0
    if name != "navy_empty_toolbar":
        ocean = _u32(session, _OCEAN_MGR)
        if ocean == 0:
            raise RuntimeError("the fixture has no map-order context")
        zone = _invoke_thiscall(
            session, _OCEAN_FIND_PORT_ZONE, ocean, records, occurrences,
            breakpoint_roles, args=(active_slot,),
        )
        if zone == 0:
            raise RuntimeError("the fixture has no port zone for the active nation")

    def spawn_four() -> None:
        spawn(3, zone, "navy-cls1")
        spawn(7, zone, "navy-cls2")
        spawn(9, zone, "navy-cls0")
        spawn(12, zone, "navy-cls3")

    def create_force() -> int:
        return _invoke_thiscall(
            session, _ZONE_CREATE_TASK_FORCE, zone, records, occurrences,
            breakpoint_roles, args=(active_slot,),
        )

    def committed_evade_force() -> int:
        spawn_four()
        created = create_force()
        if created == 0:
            raise RuntimeError("could not commit a task force")
        session.assign(f"*(char*)0x{created + 0x26:08x}", 0)
        _invoke_thiscall(
            session, _TF_SUBMIT_ORDERS, created, records, occurrences,
            breakpoint_roles, args=(9, 0),
        )
        return created

    if name in (
        "navy_toolbar_counts",
        "navy_select_ship",
        "navy_set_aggression",
        "navy_cancel_order",
        "navy_zone_target",
        "navy_province_target",
    ):
        force = committed_evade_force()

    if name == "navy_create_force":
        spawn(3, zone, "navy-create-cls1")
        spawn(9, zone, "navy-create-cls0")
        created = create_force()
        if created == 0:
            raise RuntimeError(
                "CreateTaskForceFromNavyOrdersForNationIfEligible returned null"
            )
        session.assign(f"*(char*)0x{created + 0x26:08x}", 0)
        _invoke_thiscall(
            session, _TF_SUBMIT_ORDERS, created, records, occurrences,
            breakpoint_roles, args=(9, 0),
        )
        return _navy_ui_result(session)

    if name == "navy_toolbar_counts" or name == "navy_empty_toolbar":
        available = [0] * 4
        selected = [-1] * 4
        if force != 0:
            counts = session.read_memory(force + 0x1E, 8)
            available = list(struct.unpack("<4h", counts))
            selected = [
                _invoke_thiscall(
                    session, _TF_GET_SELECTED, force, records, occurrences,
                    breakpoint_roles, args=(slot,),
                )
                for slot in range(4)
            ]
        return _navy_ui_result(
            session, {"available": available, "selected": selected}
        )

    if name == "navy_select_ship":
        _invoke_thiscall(
            session, _TF_SELECT_SLOT, force, records, occurrences,
            breakpoint_roles, args=(0, 0),
        )
        return _navy_ui_result(session)

    if name == "navy_set_aggression":
        _invoke_thiscall(
            session, _TF_SET_AGGRESSION, force, records, occurrences,
            breakpoint_roles, args=(2,),
        )
        return _navy_ui_result(session)

    if name == "navy_submit_order":
        spawn(3, zone, "navy-submit-cls1")
        spawn(9, zone, "navy-submit-cls0")
        created = create_force()
        if created == 0:
            raise RuntimeError(
                "CreateTaskForceFromNavyOrdersForNationIfEligible returned null"
            )
        session.assign(f"*(char*)0x{created + 0x26:08x}", 0)
        _invoke_thiscall(
            session, _TF_SUBMIT_ORDERS, created, records, occurrences,
            breakpoint_roles, args=(9, 0),
        )
        return _navy_ui_result(session)

    if name == "navy_cancel_order":
        _invoke_thiscall(
            session, _TF_CANCEL_ORDERS, force, records, occurrences,
            breakpoint_roles, args=(0,),
        )
        return _navy_ui_result(session)

    if name == "navy_zone_target":
        other = _u32(session, zone + 0x18)
        if other == 0:
            other = _u32(session, _MAP_ACTION_CONTEXT_LIST_HEAD)
        legal = (
            _invoke_thiscall(
                session, _TF_VALID_TARGET_ZONE, force, records, occurrences,
                breakpoint_roles, args=(zone,),
            )
            & 0xFF
            != 0
        )
        illegal = False
        if other != 0 and other != zone:
            illegal = (
                _invoke_thiscall(
                    session, _TF_VALID_TARGET_ZONE, force, records,
                    occurrences, breakpoint_roles, args=(other,),
                )
                & 0xFF
                != 0
            )
        child = _u32(session, force + 0x10)
        actives = []
        child_types = []
        while child != 0:
            actives.append(_u8(session, child + 0x0C))
            child_types.append(_s16(session, _u32(session, child) + 0x04))
            child = _u32(session, child + 0x04)
        distance = _invoke_thiscall(
            session, 0x005610B0, zone, records, occurrences,
            breakpoint_roles, args=(other,),
        )
        return _navy_ui_result(
            session,
            {
                "legal": bool(legal),
                "illegal": bool(illegal),
                "actives": actives,
                "child_types": child_types,
                "distance": distance & 0xFFFF,
                "zone_ord": _zone_ordinal(session, zone),
                "force_loc_ord": _zone_ordinal(
                    session, _u32(session, force + 0x18)
                ),
                "other_ord": _zone_ordinal(session, other),
            },
        )

    if name == "navy_province_target":
        province = -1
        map_state = _u32(session, _GLOBAL_MAP_STATE)
        base = _u32(session, map_state + 0x10)
        owners = b""
        total = _PROVINCE_COUNT * _PROVINCE_STRIDE
        for offset in range(0, total, 0x2000):
            owners += session.read_memory(
                base + offset, min(0x2000, total - offset)
            )
        for index in range(_PROVINCE_COUNT):
            if struct.unpack(
                "<b", owners[index * _PROVINCE_STRIDE :][:1]
            )[0] >= 0:
                province = index
                break
        if province < 0:
            raise RuntimeError("the fixture has no owned province")
        legal = (
            _invoke_thiscall(
                session, _TF_VALID_TARGET_PROVINCE, force, records,
                occurrences, breakpoint_roles,
                args=(_province_record(session, province),),
            )
            & 0xFF
            != 0
        )
        return _navy_ui_result(session, bool(legal))

    if name == "navy_selection_cycling":
        spawn(3, zone, "navy-cycle-cls1")
        next_zone = 0
        candidate = _u32(session, zone + 0x18)
        while candidate != 0:
            displayable = (
                _invoke_thiscall(
                    session, _ZONE_CAN_DISPLAY, candidate, records,
                    occurrences, breakpoint_roles, args=(active_slot, 0),
                )
                & 0xFF
            )
            if displayable != 0:
                next_zone = candidate
                break
            candidate = _u32(session, candidate + 0x18)
        return _navy_ui_result(session, _zone_ordinal(session, next_zone))

    raise RuntimeError(f"unknown navy ui drive {name!r}")


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
        needs = list(
            struct.unpack(
                f"<{_NATION_SLOT_COUNT}h",
                session.read_memory(nation + 0x14, 2 * _NATION_SLOT_COUNT),
            )
        )
        boycotts = list(session.read_memory(nation + 0x918, _NATION_SLOT_COUNT))
        nations.append(
            {
                "treasury": _eval_int(session, f"*(int*)0x{nation + 0x10:08x}"),
                "needs": needs,
                "boycotts": boycotts,
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
                    _invoke_thiscall(
                        session,
                        _SRAND,
                        0,
                        records,
                        occurrences,
                        breakpoint_roles,
                        args=(0x1234,),
                    )
                    session.assign(
                        f"*(unsigned int*)0x{_MAP_GENERATION_RNG:08x}",
                        0x1234,
                    )
                    session.assign(
                        f"*(unsigned int*)0x{_ZONE_STATUS_RNG:08x}",
                        0x1234,
                    )
                    rng_before = _capture_rng_state(
                        session, records, occurrences, breakpoint_roles
                    )
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
                    elif scenario.drive == "reassess_control_sea_missions":
                        _drive_reassess_missions(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_missions(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_REASSESS_MISSIONS
                    elif (
                        scenario.drive
                        == "reassess_control_sea_missions_damaged_ship"
                    ):
                        _drive_reassess_missions_damaged(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_missions(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_REASSESS_MISSIONS_DAMAGED
                    elif scenario.drive == "ai_naval_industry_development":
                        _drive_ai_naval_development(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_ai_development(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_AI_NAVAL_DEVELOPMENT
                    elif scenario.drive in (
                        "military_phase_naval_encounter",
                        "military_phase_naval_escalation",
                        "military_phase_naval_tier_exhaustion",
                    ):
                        result_fields = _drive_military_phase_naval_encounter(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            attacker_type=(
                                9
                                if scenario.drive
                                == "military_phase_naval_escalation"
                                else 3
                            ),
                            tier_exhaustion=(
                                scenario.drive
                                == "military_phase_naval_tier_exhaustion"
                            ),
                        )
                        result_fields.update(_capture_military_phase(session))
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "strategic_naval_battle_matrix":
                        result_fields = _drive_strategic_naval_battle_matrix(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                        )
                        result_probe = CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX
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
                    elif scenario.drive == "consecutive_turn_sequence":
                        result_fields = _drive_consecutive_turn_sequence(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE
                    elif scenario.drive == "check_technology_advances":
                        _drive_check_technology_advances(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_technology(session)
                        result_probe = CHECKPOINT_CHECK_TECH_ADVANCES
                    elif (
                        scenario.drive
                        == "check_technology_advances_ai_purchase"
                    ):
                        _drive_check_technology_advances_ai_purchase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_technology(session)
                        result_probe = CHECKPOINT_CHECK_TECH_ADVANCES_AI
                    elif (
                        scenario.drive
                        == "technology_naval_capability_upgrade"
                    ):
                        _drive_technology_naval_capability_upgrade(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_technology(session)
                        result_probe = CHECKPOINT_TECH_NAVAL_UPGRADE
                    elif (
                        scenario.drive
                        == "technology_naval_capability_sequence"
                    ):
                        _drive_technology_naval_capability_upgrade(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            technology_ids=(4, 9, 15, 21, 24, 27),
                            with_ships=False,
                        )
                        result_fields = _capture_technology(session)
                        result_probe = CHECKPOINT_TECH_NAVAL_SEQUENCE
                    elif scenario.drive == "turn_stop_technology":
                        _drive_turn_stop_technology(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_technology(session)
                        result_probe = CHECKPOINT_TURN_STOP_TECHNOLOGY
                    elif scenario.drive in _PLAYER_POLICY_ALL_SCENARIOS:
                        result_fields = _drive_player_diplomacy_policy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            scenario.drive,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_stop_trade":
                        result_fields = _drive_turn_stop_trade(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_TURN_STOP_TRADE
                    elif scenario.drive == "trade_phase_sell_only":
                        result_fields = {"pre": _capture_trade_phase(session)}
                        _drive_trade_phase(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            buy_clothing=False,
                        )
                        result_fields.update(_capture_trade_phase(session))
                        result_fields["toggle"] = 0
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "trade_market_price":
                        result_fields = _drive_trade_market_price(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "military_maintenance":
                        result_fields = _drive_military_maintenance(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "diplomacy_offer_gate":
                        result_fields = _drive_diplomacy_offer_gate(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "quarter_gate_off_decade":
                        result_fields = _drive_quarter_gate(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive == "return_to_map_clears_notice_queues"
                    ):
                        result_fields = _drive_return_to_map(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_diplomacy_phase":
                        result_fields = _drive_turn_state_diplomacy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            6,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_diplomacy_offer_gate":
                        result_fields = _drive_turn_state_diplomacy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            0x0D,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_quarter_gate":
                        result_fields = _drive_turn_state_quarter_gate(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_return_to_map":
                        result_fields = _drive_turn_state_diplomacy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            0x12,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_combat_moves":
                        result_fields = _drive_turn_state_combat_moves(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_military_cleanup":
                        result_fields = _drive_turn_state_military_cleanup(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_state_ai_replan_perturbed":
                        result_fields = _drive_turn_state_military_cleanup(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            perturb_ai=True,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive
                        == "turn_state_ai_reassess_damaged_ship"
                    ):
                        result_fields = _drive_turn_state_military_cleanup(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            perturb_damaged_mission=True,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive == "province_loss_with_stationed_unit"
                    ):
                        result_fields = _drive_province_loss(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "province_owner_ocean_context":
                        result_fields = _drive_province_ocean(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "completed_rail_section":
                        result_fields = _drive_completed_rail_section(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "issued_rail_section":
                        result_fields = _drive_issued_rail_section(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "completed_resource_development":
                        result_fields = _drive_completed_resource_development(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "nation_resource_yield_rebuild":
                        result_fields = _drive_yield_rebuild(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive
                        == "ai_nation_resource_yield_rebuild_clamps_targets"
                    ):
                        result_fields = _drive_yield_rebuild_clamps(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive
                        == "nation_resource_yield_rebuild_multiple_towns"
                    ):
                        result_fields = _drive_yield_rebuild_multiple_towns(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "owned_region_development":
                        result_fields = _drive_owned_region_development(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "specialist_recruitment":
                        result_fields = _drive_specialist_recruitment(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "navy_growth_pending":
                        result_fields = _drive_navy_growth_pending(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "army_growth_selected_general":
                        result_fields = _drive_army_growth_selected_general(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive == "interactive_army_battle_done"
                    ):
                        result_fields = _drive_interactive_battle_done(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive == "interactive_army_battle_move"
                    ):
                        result_fields = _drive_interactive_battle_move(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif (
                        scenario.drive == "interactive_army_battle_retreat"
                    ):
                        result_fields = _drive_interactive_battle_retreat(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "auto_resolve_land_battle":
                        result_fields = _drive_auto_resolve_land_battle(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "advisory_map_missions_case16":
                        result_fields = _drive_advisory_case16(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "army_movement_give_orders":
                        result_fields = _drive_army_movement(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in _CITY_ITEM_ORDER_SCENARIOS:
                        result_fields = _drive_city_item_order(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            quantity=(
                                1
                                if scenario.drive
                                == "city_item_order_increase"
                                else 0
                            ),
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "opening_civilian_grant":
                        result_fields = _drive_opening_civilian_grant(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "opening_home_city_setup":
                        result_fields = _drive_opening_home_city_setup(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in _PENDING_STATUS_SCENARIOS:
                        result_fields = _drive_pending_status(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            navy_growth_only=(
                                scenario.drive
                                == "newspaper_navy_growth_reward_levels"
                            ),
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in (
                        "construct_newspaper_page",
                        "construct_newspaper_page_misc_event",
                    ):
                        result_fields = _drive_construct_newspaper(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            queue_misc_event=(
                                scenario.drive
                                == "construct_newspaper_page_misc_event"
                            ),
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "turn_stop_newspaper":
                        result_fields = _drive_turn_stop_newspaper(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in _ARMY_UI_SCENARIOS:
                        result_fields = _drive_army_ui(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            scenario.drive,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in _NAVY_UI_SCENARIOS:
                        result_fields = _drive_navy_ui(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            scenario.drive,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in _NATION_ECONOMY_SPECS:
                        result_fields = _drive_nation_economy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            scenario.drive,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in _DIPLOMACY_ECONOMY_SCENARIOS:
                        result_fields = _drive_diplomacy_economy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            scenario.drive,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive == "season_advance_clears_status_flags":
                        _drive_season_advance(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_turn_state(session)
                        result_probe = CHECKPOINT_SEASON_ADVANCE
                    elif (
                        scenario.drive
                        == "elimination_phase_with_landed_great_powers"
                    ):
                        result_fields = _drive_elimination_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_ELIMINATION_PHASE
                    elif (
                        scenario.drive
                        == "turn_alerts_skip_first_economic_turn"
                    ):
                        result_fields = _drive_turn_alerts_first(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_TURN_ALERTS_FIRST
                    elif scenario.drive == "turn_alerts_later_turn":
                        result_fields = _drive_turn_alerts_later(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_TURN_ALERTS_LATER
                    elif (
                        scenario.drive
                        == "great_power_pressure_human_debt"
                    ):
                        result_fields = _drive_pressure_human_debt(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_PRESSURE_HUMAN_DEBT
                    elif (
                        scenario.drive
                        == "great_power_pressure_ai_noop"
                    ):
                        result_fields = _drive_pressure_ai_noop(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_probe = CHECKPOINT_PRESSURE_AI_NOOP
                    elif scenario.drive == "turn_stop_deal_book":
                        sim_mgr = _u32(session, _SIM_MGR)
                        session.assign(
                            f"*(int*)0x{sim_mgr + 0x04:08x}", 0x0C
                        )
                        _invoke_thiscall(
                            session,
                            _ADVANCE_TURN_STATE,
                            sim_mgr,
                            records,
                            occurrences,
                            breakpoint_roles,
                        )
                        result_fields = _capture_turn_state(session)
                        result_probe = CHECKPOINT_TURN_STOP_DEAL_BOOK
                    elif (
                        scenario.drive == "turn_stop_city_and_transport"
                    ):
                        sim_mgr = _u32(session, _SIM_MGR)
                        session.assign(
                            f"*(int*)0x{sim_mgr + 0x04:08x}", 0x0B
                        )
                        _invoke_virtual(
                            session,
                            sim_mgr,
                            0x54,
                            records,
                            occurrences,
                            breakpoint_roles,
                        )
                        result_fields = _capture_turn_state(session)
                        result_probe = CHECKPOINT_TURN_STOP_CITY_TRANSPORT
                    elif scenario.drive in (
                        "interactive_army_battle_melee",
                        "interactive_army_battle_ranged",
                    ):
                        result_fields = _drive_interactive_battle_attack(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            0x0A
                            if scenario.drive
                            == "interactive_army_battle_melee"
                            else 5,
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in (
                        "combat_moves_uncontested",
                        "combat_moves_creates_battle",
                        "combat_moves_resumes_after_battle",
                        "combat_moves_battle_then_later_movement",
                    ):
                        result_fields = _drive_combat_moves(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            {
                                "combat_moves_uncontested": "uncontested",
                                "combat_moves_creates_battle": "battle",
                                "combat_moves_resumes_after_battle": (
                                    "two_battles"
                                ),
                                "combat_moves_battle_then_later_movement": (
                                    "battle_then_moves"
                                ),
                            }[scenario.drive],
                        )
                        result_probe = scenario.result_checkpoint_id
                    elif scenario.drive in (
                        "navy_battle_accepted_deploy_tiles",
                        "navy_battle_player_as_defender",
                    ):
                        result_fields = _drive_navy_battle_deploy(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            scenario.drive
                            == "navy_battle_player_as_defender",
                        )
                        result_probe = scenario.result_checkpoint_id
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
                    result_fields["rng_contract"] = {
                        "before": rng_before,
                        "after": _capture_rng_state(
                            session, records, occurrences, breakpoint_roles
                        ),
                    }
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
    native_result = None
    if scenario.drive in {
        "diplomacy_phase",
        "trade_phase",
        "city_transport_phase",
        "civilians_phase",
        "military_phase",
        "military_phase_naval_encounter",
        "military_phase_naval_escalation",
        "military_phase_naval_tier_exhaustion",
        "strategic_naval_battle_matrix",
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
        "turn_state_ai_replan_perturbed",
        "turn_state_ai_reassess_damaged_ship",
        "turn_state_combat_moves",
        "turn_state_military_cleanup",
        "recompute_nation_order_priority_metrics",
        "reassess_control_sea_missions",
        "reassess_control_sea_missions_damaged_ship",
        "ai_naval_industry_development",
        "consecutive_turn_sequence",
        "check_technology_advances",
        "check_technology_advances_ai_purchase",
        "technology_naval_capability_upgrade",
        "technology_naval_capability_sequence",
        "turn_stop_technology",
        "season_advance_clears_status_flags",
        "elimination_phase_with_landed_great_powers",
        "turn_alerts_skip_first_economic_turn",
        "great_power_pressure_human_debt",
        "great_power_pressure_ai_noop",
        "turn_stop_deal_book",
        "turn_stop_city_and_transport",
        "turn_stop_trade",
        *_PLAYER_POLICY_ALL_SCENARIOS,
        *_NATION_ECONOMY_SCENARIOS,
        *_DIPLOMACY_ECONOMY_SCENARIOS,
        *_PROVINCE_SCENARIOS,
        *_DEVELOPMENT_SCENARIOS,
        *_YIELD_SCENARIOS,
        *_GROWTH_SCENARIOS,
        *_TACTICAL_SNAPSHOT_SCENARIOS,
        *_ARMY_MILITARY_SCENARIOS,
        *_CITY_ITEM_ORDER_SCENARIOS,
        *_OPENING_SCENARIOS,
        *_PENDING_STATUS_SCENARIOS,
        *_NEWS_SCENARIOS,
        *_ARMY_UI_SCENARIOS,
        *_NAVY_UI_SCENARIOS,
        "owned_region_development",
        "specialist_recruitment",
        "advisory_map_missions_case16",
        "turn_alerts_later_turn",
        "interactive_army_battle_melee",
        "interactive_army_battle_ranged",
        "navy_battle_accepted_deploy_tiles",
        "navy_battle_player_as_defender",
        "combat_moves_uncontested",
        "combat_moves_creates_battle",
        "combat_moves_resumes_after_battle",
        "combat_moves_battle_then_later_movement",
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
        elif scenario.drive in (
            "military_phase_naval_encounter",
            "military_phase_naval_escalation",
        ):
            recomp_observation = normalize_native_military_phase(native_result)
        elif scenario.drive == "military_phase_naval_tier_exhaustion":
            recomp_observation = (
                normalize_native_military_phase_naval_tier_exhaustion(
                    native_result
                )
            )
        elif scenario.drive == "strategic_naval_battle_matrix":
            recomp_observation = normalize_native_strategic_naval_battle_matrix(
                native_result
            )
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
        elif scenario.drive in (
            "reassess_control_sea_missions",
            "reassess_control_sea_missions_damaged_ship",
        ):
            recomp_observation = normalize_native_reassess_missions(
                native_result
            )
        elif scenario.drive == "ai_naval_industry_development":
            recomp_observation = normalize_native_ai_naval_development(
                native_result
            )
        elif scenario.drive == "consecutive_turn_sequence":
            recomp_observation = normalize_native_consecutive_turn_sequence(
                native_result
            )
        elif scenario.drive == "check_technology_advances":
            recomp_observation = normalize_native_check_technology_advances(
                native_result
            )
        elif scenario.drive == "check_technology_advances_ai_purchase":
            recomp_observation = normalize_native_check_technology_advances(
                native_result,
                checkpoint_id=CHECKPOINT_CHECK_TECH_ADVANCES_AI,
                action_id="check_technology_advances_ai_purchase.run",
            )
        elif scenario.drive == "technology_naval_capability_upgrade":
            recomp_observation = normalize_native_check_technology_advances(
                native_result,
                checkpoint_id=CHECKPOINT_TECH_NAVAL_UPGRADE,
                action_id="technology_naval_capability_upgrade.run",
            )
        elif scenario.drive == "technology_naval_capability_sequence":
            recomp_observation = normalize_native_check_technology_advances(
                native_result,
                checkpoint_id=CHECKPOINT_TECH_NAVAL_SEQUENCE,
                action_id="technology_naval_capability_sequence.run",
            )
        elif scenario.drive == "turn_stop_technology":
            recomp_observation = normalize_native_check_technology_advances(
                native_result,
                checkpoint_id=CHECKPOINT_TURN_STOP_TECHNOLOGY,
                action_id="turn_stop_technology.run",
            )
        elif scenario.drive == "season_advance_clears_status_flags":
            recomp_observation = normalize_native_season_advance(
                native_result
            )
        elif (
            scenario.drive
            == "elimination_phase_with_landed_great_powers"
        ):
            recomp_observation = normalize_native_elimination_phase(
                native_result
            )
        elif (
            scenario.drive == "turn_alerts_skip_first_economic_turn"
        ):
            recomp_observation = normalize_native_turn_alerts_first(
                native_result
            )
        elif scenario.drive in (
            "great_power_pressure_human_debt",
            "great_power_pressure_ai_noop",
        ):
            recomp_observation = normalize_native_great_power_pressure(
                native_result,
                scenario.result_checkpoint_id,
            )
        elif scenario.drive in (
            "turn_stop_deal_book",
            "turn_stop_city_and_transport",
        ):
            recomp_observation = normalize_native_turn_stop_state(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive == "turn_stop_trade":
            recomp_observation = normalize_native_turn_stop_trade(
                native_result
            )
        elif scenario.drive in _PLAYER_POLICY_ALL_SCENARIOS:
            recomp_observation = normalize_native_player_diplomacy_policy(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _NATION_ECONOMY_SCENARIOS:
            recomp_observation = normalize_native_nation_economy(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _DIPLOMACY_ECONOMY_SCENARIOS:
            recomp_observation = normalize_native_player_diplomacy_policy(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive == "province_loss_with_stationed_unit":
            recomp_observation = normalize_native_province_loss(native_result)
        elif scenario.drive == "province_owner_ocean_context":
            recomp_observation = normalize_native_province_ocean(native_result)
        elif scenario.drive in _DEVELOPMENT_SCENARIOS:
            recomp_observation = normalize_native_development(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _YIELD_SCENARIOS + (
            "owned_region_development",
        ):
            recomp_observation = normalize_native_yield_rebuild(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive == "specialist_recruitment":
            recomp_observation = normalize_native_specialist_recruitment(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _GROWTH_SCENARIOS + _ARMY_MILITARY_SCENARIOS:
            recomp_observation = normalize_native_growth(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive == "advisory_map_missions_case16":
            recomp_observation = normalize_native_advisory(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _TACTICAL_SNAPSHOT_SCENARIOS:
            recomp_observation = normalize_native_battle_snapshots(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _CITY_ITEM_ORDER_SCENARIOS:
            recomp_observation = normalize_native_city_item_order(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _OPENING_SCENARIOS:
            recomp_observation = normalize_native_opening(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _PENDING_STATUS_SCENARIOS:
            recomp_observation = normalize_native_pending_status(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _NEWS_SCENARIOS:
            recomp_observation = normalize_native_news(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _ARMY_UI_SCENARIOS:
            recomp_observation = normalize_native_army_ui(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in _NAVY_UI_SCENARIOS:
            recomp_observation = normalize_native_navy_ui(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive == "turn_alerts_later_turn":
            recomp_observation = normalize_native_turn_alerts_later(
                native_result
            )
        elif scenario.drive in (
            "interactive_army_battle_melee",
            "interactive_army_battle_ranged",
        ):
            recomp_observation = normalize_native_battle_attack(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in (
            "navy_battle_accepted_deploy_tiles",
            "navy_battle_player_as_defender",
        ):
            recomp_observation = normalize_native_navy_battle_deploy(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive in (
            "combat_moves_uncontested",
            "combat_moves_creates_battle",
            "combat_moves_resumes_after_battle",
            "combat_moves_battle_then_later_movement",
        ):
            recomp_observation = normalize_native_combat_moves(
                native_result, scenario.result_checkpoint_id
            )
        elif scenario.drive == "second_turn_military_cleanup":
            recomp_observation = normalize_native_military_cleanup(
                native_result,
                checkpoint_id=CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
            )
        elif scenario.drive == "turn_state_combat_moves":
            recomp_observation = normalize_native_military_phase(
                native_result,
                checkpoint_id=CHECKPOINT_TURN_STATE_COMBAT_MOVES,
                action_id=ACTION_TURN_STATE_COMBAT_MOVES,
                include_rng=True,
            )
        elif scenario.drive in (
            "turn_state_military_cleanup",
            "turn_state_ai_replan_perturbed",
            "turn_state_ai_reassess_damaged_ship",
        ):
            recomp_observation = (
                normalize_native_turn_state_military_cleanup(
                    native_result,
                    checkpoint_id=scenario.result_checkpoint_id,
                    action_id=scenario.action_id,
                )
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
    elif result_checkpoint == CHECKPOINT_NAVAL_TIER_EXHAUSTION_PHASE:
        retail_observation = (
            normalize_retail_military_phase_naval_tier_exhaustion(
                retail_records[0]["fields"]
            )
        )
    elif result_checkpoint == CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX:
        retail_observation = normalize_retail_strategic_naval_battle_matrix(
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
    elif result_checkpoint == CHECKPOINT_TURN_STATE_COMBAT_MOVES:
        retail_observation = normalize_retail_military_phase(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_TURN_STATE_COMBAT_MOVES,
            action_id=ACTION_TURN_STATE_COMBAT_MOVES,
            include_rng=True,
        )
    elif result_checkpoint == CHECKPOINT_TURN_STATE_MILITARY_CLEANUP:
        retail_observation = (
            normalize_retail_turn_state_military_cleanup(
                retail_records[0]["fields"]
            )
        )
    elif result_checkpoint == CHECKPOINT_TURN_STATE_AI_REPLAN:
        retail_observation = (
            normalize_retail_turn_state_military_cleanup(
                retail_records[0]["fields"],
                checkpoint_id=CHECKPOINT_TURN_STATE_AI_REPLAN,
                action_id=ACTION_TURN_STATE_AI_REPLAN,
            )
        )
    elif result_checkpoint == CHECKPOINT_TURN_STATE_AI_REASSESS_DAMAGED:
        retail_observation = (
            normalize_retail_turn_state_military_cleanup(
                retail_records[0]["fields"],
                checkpoint_id=CHECKPOINT_TURN_STATE_AI_REASSESS_DAMAGED,
                action_id=ACTION_TURN_STATE_AI_REASSESS_DAMAGED,
            )
        )
    elif result_checkpoint == CHECKPOINT_RECOMPUTE_METRICS:
        retail_observation = normalize_retail_recompute_metrics(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (
        CHECKPOINT_REASSESS_MISSIONS,
        CHECKPOINT_REASSESS_MISSIONS_DAMAGED,
    ):
        retail_observation = normalize_retail_reassess_missions(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_AI_NAVAL_DEVELOPMENT:
        retail_observation = normalize_retail_ai_naval_development(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE:
        retail_observation = normalize_retail_consecutive_turn_sequence(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_CHECK_TECH_ADVANCES:
        retail_observation = normalize_retail_check_technology_advances(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_CHECK_TECH_ADVANCES_AI:
        retail_observation = normalize_retail_check_technology_advances(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_CHECK_TECH_ADVANCES_AI,
            action_id="check_technology_advances_ai_purchase.run",
        )
    elif result_checkpoint == CHECKPOINT_TECH_NAVAL_UPGRADE:
        retail_observation = normalize_retail_check_technology_advances(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_TECH_NAVAL_UPGRADE,
            action_id="technology_naval_capability_upgrade.run",
        )
    elif result_checkpoint == CHECKPOINT_TECH_NAVAL_SEQUENCE:
        retail_observation = normalize_retail_check_technology_advances(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_TECH_NAVAL_SEQUENCE,
            action_id="technology_naval_capability_sequence.run",
        )
    elif result_checkpoint == CHECKPOINT_TURN_STOP_TECHNOLOGY:
        retail_observation = normalize_retail_check_technology_advances(
            retail_records[0]["fields"],
            checkpoint_id=CHECKPOINT_TURN_STOP_TECHNOLOGY,
            action_id="turn_stop_technology.run",
        )
    elif result_checkpoint == CHECKPOINT_SEASON_ADVANCE:
        retail_observation = normalize_retail_season_advance(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_ELIMINATION_PHASE:
        retail_observation = normalize_retail_elimination_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_TURN_ALERTS_FIRST:
        retail_observation = normalize_retail_turn_alerts_first(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (
        CHECKPOINT_PRESSURE_HUMAN_DEBT,
        CHECKPOINT_PRESSURE_AI_NOOP,
    ):
        retail_observation = normalize_retail_great_power_pressure(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        CHECKPOINT_TURN_STOP_DEAL_BOOK,
        CHECKPOINT_TURN_STOP_CITY_TRANSPORT,
    ):
        retail_observation = normalize_retail_turn_stop_state(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint == CHECKPOINT_TURN_STOP_TRADE:
        retail_observation = normalize_retail_turn_stop_trade(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _PLAYER_POLICY_ALL_SCENARIOS
    ):
        retail_observation = normalize_retail_player_diplomacy_policy(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _NATION_ECONOMY_SCENARIOS
    ):
        retail_observation = normalize_retail_nation_economy(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _DIPLOMACY_ECONOMY_SCENARIOS
    ):
        retail_observation = normalize_retail_player_diplomacy_policy(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint == "province_loss_with_stationed_unit.resolved":
        retail_observation = normalize_retail_province_loss(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == "province_owner_ocean_context.resolved":
        retail_observation = normalize_retail_province_ocean(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _DEVELOPMENT_SCENARIOS
    ):
        retail_observation = normalize_retail_development(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved"
        for _name in _YIELD_SCENARIOS + ("owned_region_development",)
    ):
        retail_observation = normalize_retail_yield_rebuild(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint == "specialist_recruitment.resolved":
        retail_observation = normalize_retail_specialist_recruitment(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint == "advisory_map_missions_case16.resolved":
        retail_observation = normalize_retail_advisory(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _TACTICAL_SNAPSHOT_SCENARIOS
    ):
        retail_observation = normalize_retail_battle_snapshots(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _CITY_ITEM_ORDER_SCENARIOS
    ):
        retail_observation = normalize_retail_city_item_order(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _OPENING_SCENARIOS
    ):
        retail_observation = normalize_retail_opening(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _PENDING_STATUS_SCENARIOS
    ):
        retail_observation = normalize_retail_pending_status(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _NEWS_SCENARIOS
    ):
        retail_observation = normalize_retail_news(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _ARMY_UI_SCENARIOS
    ):
        retail_observation = normalize_retail_army_ui(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved" for _name in _NAVY_UI_SCENARIOS
    ):
        retail_observation = normalize_retail_navy_ui(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        _name + ".resolved"
        for _name in _GROWTH_SCENARIOS + _ARMY_MILITARY_SCENARIOS
    ):
        retail_observation = normalize_retail_growth(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint == CHECKPOINT_TURN_ALERTS_LATER:
        retail_observation = normalize_retail_turn_alerts_later(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (
        CHECKPOINT_BATTLE_MELEE,
        CHECKPOINT_BATTLE_RANGED,
    ):
        retail_observation = normalize_retail_battle_attack(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint in (
        CHECKPOINT_NAVY_BATTLE_DEPLOY,
        CHECKPOINT_NAVY_BATTLE_DEFENDER,
    ):
        retail_observation = normalize_retail_navy_battle_deploy(
            retail_records[0]["fields"], result_checkpoint
        )
    elif result_checkpoint == CHECKPOINT_SECOND_TURN_SEQUENCE:
        retail_observation = normalize_retail_second_turn_sequence(
            retail_records[0]["fields"]
        )
    elif result_checkpoint in (
        CHECKPOINT_COMBAT_UNCONTESTED,
        CHECKPOINT_COMBAT_BATTLE,
        CHECKPOINT_COMBAT_RESUME,
        CHECKPOINT_COMBAT_THEN_MOVES,
    ):
        retail_observation = normalize_retail_combat_moves(
            retail_records[0]["fields"], result_checkpoint
        )
    else:
        retail_observation = normalize_retail_combined_map(retail_records[0]["fields"])
    if native_result is not None:
        recomp_observation["rng"] = normalize_native_rng_contract(native_result)
        retail_observation["rng"] = normalize_retail_rng_contract(
            retail_records[0]["fields"]
        )
    validate_checkpoint(retail_observation)
    validate_checkpoint(recomp_observation)
    divergence = first_checkpoint_difference(retail_observation, recomp_observation)
    result = {
        "scenario": scenario.name,
        "evidence_kind": "retail_differential",
        "scenario_class": _scenario_classification(scenario.name),
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
