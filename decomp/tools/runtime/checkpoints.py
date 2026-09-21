"""Shared semantic checkpoint identifiers and normalized observation schemas.

The native scenarios and retail GDB tape intentionally do not share execution code.
They meet only here, after each side has produced observations at a named checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


ACTION_RANDOM_GAME_SETUP = "random_game.setup"
ACTION_COMBINED_MAP_ENTRY = "combined_map.enter"
ACTION_CITY_ACTIVATION = "city.activate"
ACTION_TURN_ADVANCEMENT = "turn.advance"
ACTION_DIPLOMACY_PHASE = "diplomacy_phase.run"
ACTION_TRADE_PHASE = "trade_phase.run"
ACTION_CITY_TRANSPORT_PHASE = "city_transport_phase.run"
ACTION_CIVILIANS_PHASE = "civilians_phase.run"
ACTION_MILITARY_PHASE = "military_phase.run"
ACTION_MILITARY_CLEANUP = "second_turn_military_cleanup.run"
ACTION_RECOMPUTE_METRICS = "recompute_nation_order_priority_metrics.run"
ACTION_REASSESS_MISSIONS = "reassess_control_sea_missions.run"
ACTION_REASSESS_MISSIONS_DAMAGED = (
    "reassess_control_sea_missions_damaged_ship.run"
)
ACTION_AI_NAVAL_DEVELOPMENT = "ai_naval_industry_development.run"
ACTION_SECOND_TURN_SEQUENCE = "second_turn_sequence.run"
ACTION_CONSECUTIVE_TURN_SEQUENCE = "consecutive_turn_sequence.run"
ACTION_CHECK_TECH_ADVANCES = "check_technology_advances.run"

CHECKPOINT_RANDOM_SETUP_READY = "random_setup.ready"
CHECKPOINT_COMBINED_MAP_READY = "combined_map.ready"
CHECKPOINT_CITY_ACTIVE = "city.active"
CHECKPOINT_TURN_ADVANCED = "turn.advanced"
CHECKPOINT_DIPLOMACY_PHASE = "diplomacy_phase.resolved"
CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE = "second_turn_diplomacy_phase.resolved"
CHECKPOINT_TRADE_PHASE = "trade_phase.resolved"
CHECKPOINT_SECOND_TURN_TRADE_PHASE = "second_turn_trade_phase.resolved"
CHECKPOINT_CITY_TRANSPORT_PHASE = "city_transport_phase.resolved"
CHECKPOINT_CIVILIANS_PHASE = "civilians_phase.resolved"
CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE = "second_turn_civilians_phase.resolved"
CHECKPOINT_MILITARY_PHASE = "military_phase.resolved"
CHECKPOINT_NAVAL_ENCOUNTER_PHASE = "military_phase_naval_encounter.resolved"
CHECKPOINT_NAVAL_ESCALATION_PHASE = "military_phase_naval_escalation.resolved"
CHECKPOINT_LAND_COMBAT_PHASE = "military_phase_land_combat.resolved"
CHECKPOINT_LAND_INTERACTIVE_PHASE = "military_phase_land_interactive.resolved"
CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE = (
    "military_phase_ships_without_orders.resolved"
)
CHECKPOINT_LAND_RETREAT_PHASE = "military_phase_land_retreat.resolved"
CHECKPOINT_SECOND_TURN_MILITARY_PHASE = "second_turn_military_phase.resolved"
CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP = "second_turn_military_cleanup.resolved"
CHECKPOINT_RECOMPUTE_METRICS = "recompute_nation_order_priority_metrics.resolved"
CHECKPOINT_REASSESS_MISSIONS = "reassess_control_sea_missions.resolved"
CHECKPOINT_REASSESS_MISSIONS_DAMAGED = (
    "reassess_control_sea_missions_damaged_ship.resolved"
)
CHECKPOINT_AI_NAVAL_DEVELOPMENT = "ai_naval_industry_development.resolved"
CHECKPOINT_SECOND_TURN_SEQUENCE = "second_turn_sequence.resolved"
CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE = "consecutive_turn_sequence.resolved"
CHECKPOINT_CHECK_TECH_ADVANCES = "check_technology_advances.resolved"


@dataclass(frozen=True)
class CheckpointSchema:
    checkpoint_id: str
    action_id: str
    native_test: str
    required_paths: tuple[str, ...]


SCHEMAS = {
    CHECKPOINT_RANDOM_SETUP_READY: CheckpointSchema(
        CHECKPOINT_RANDOM_SETUP_READY,
        ACTION_RANDOM_GAME_SETUP,
        "random_game_easy_skips_capital",
        ("turn_event", "active_view", "nation.active"),
    ),
    CHECKPOINT_COMBINED_MAP_READY: CheckpointSchema(
        CHECKPOINT_COMBINED_MAP_READY,
        ACTION_COMBINED_MAP_ENTRY,
        "load_saved_game",
        (
            "turn_event",
            "active_view",
            "nation.active",
            "nation.economic_turn",
            "map.present",
            "map.wrap",
            "city_orders.city_present",
            "city_orders.production_orders",
            "city_orders.production_flags",
        ),
    ),
    CHECKPOINT_CITY_ACTIVE: CheckpointSchema(
        CHECKPOINT_CITY_ACTIVE,
        ACTION_CITY_ACTIVATION,
        "city_screen_opens",
        ("turn_event", "active_view", "nation.active", "city_orders.city_present"),
    ),
    CHECKPOINT_TURN_ADVANCED: CheckpointSchema(
        CHECKPOINT_TURN_ADVANCED,
        ACTION_TURN_ADVANCEMENT,
        "easy_turns_advance",
        ("turn_event", "nation.active", "nation.economic_turn"),
    ),
    CHECKPOINT_DIPLOMACY_PHASE: CheckpointSchema(
        CHECKPOINT_DIPLOMACY_PHASE,
        ACTION_DIPLOMACY_PHASE,
        "diplomacy_phase_applies_grant_and_consulate",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "last_processed_nation",
            "diplomacy.nations",
        ),
    ),
    CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE,
        ACTION_DIPLOMACY_PHASE,
        "second_turn_diplomacy_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "last_processed_nation",
            "diplomacy.nations",
        ),
    ),
    CHECKPOINT_TRADE_PHASE: CheckpointSchema(
        CHECKPOINT_TRADE_PHASE,
        ACTION_TRADE_PHASE,
        "trade_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "trade.market",
            "trade.nations",
        ),
    ),
    CHECKPOINT_SECOND_TURN_TRADE_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_TRADE_PHASE,
        ACTION_TRADE_PHASE,
        "second_turn_trade_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "trade.market",
            "trade.nations",
        ),
    ),
    CHECKPOINT_CITY_TRANSPORT_PHASE: CheckpointSchema(
        CHECKPOINT_CITY_TRANSPORT_PHASE,
        ACTION_CITY_TRANSPORT_PHASE,
        "city_and_transport_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "city_transport.nations",
            "city_transport.regions",
        ),
    ),
    CHECKPOINT_CIVILIANS_PHASE: CheckpointSchema(
        CHECKPOINT_CIVILIANS_PHASE,
        ACTION_CIVILIANS_PHASE,
        "civilians_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "civilians.units",
            "civilians.nations",
        ),
    ),
    CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE,
        ACTION_CIVILIANS_PHASE,
        "second_turn_civilians_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "civilians.units",
            "civilians.nations",
        ),
    ),
    CHECKPOINT_MILITARY_PHASE: CheckpointSchema(
        CHECKPOINT_MILITARY_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_NAVAL_ENCOUNTER_PHASE: CheckpointSchema(
        CHECKPOINT_NAVAL_ENCOUNTER_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_naval_encounter",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_NAVAL_ESCALATION_PHASE: CheckpointSchema(
        CHECKPOINT_NAVAL_ESCALATION_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_naval_escalation",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_LAND_COMBAT_PHASE: CheckpointSchema(
        CHECKPOINT_LAND_COMBAT_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_land_combat",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "military.land_battle",
            "military.province_owners",
        ),
    ),
    CHECKPOINT_LAND_INTERACTIVE_PHASE: CheckpointSchema(
        CHECKPOINT_LAND_INTERACTIVE_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_land_interactive",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "military.land_battle",
            "military.province_owners",
        ),
    ),
    CHECKPOINT_LAND_RETREAT_PHASE: CheckpointSchema(
        CHECKPOINT_LAND_RETREAT_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_land_retreat",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "military.land_battle",
            "military.province_owners",
        ),
    ),
    CHECKPOINT_SECOND_TURN_MILITARY_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_MILITARY_PHASE,
        ACTION_MILITARY_PHASE,
        "second_turn_military_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
        ACTION_MILITARY_CLEANUP,
        "second_turn_military_cleanup",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military_cleanup.region_scores",
            "military_cleanup.city_score_total",
            "military_cleanup.queue_divergence",
            "military_cleanup.mobile_score",
            "military_cleanup.mobile_divergence",
            "military_cleanup.combined_divergence",
            "military_cleanup.weighted_military",
            "military_cleanup.expansion_pressure",
            "military_cleanup.unit_divergence",
            "military_cleanup.mission_pressure",
        ),
    ),
    CHECKPOINT_RECOMPUTE_METRICS: CheckpointSchema(
        CHECKPOINT_RECOMPUTE_METRICS,
        ACTION_RECOMPUTE_METRICS,
        "recompute_nation_order_priority_metrics",
        (
            "queue_divergence",
            "mobile_score",
            "mobile_divergence",
            "combined_divergence",
            "weighted_military",
            "expansion_pressure",
            "unit_divergence",
            "mission_pressure",
        ),
    ),
    CHECKPOINT_REASSESS_MISSIONS: CheckpointSchema(
        CHECKPOINT_REASSESS_MISSIONS,
        ACTION_REASSESS_MISSIONS,
        "reassess_control_sea_missions",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "missions",
        ),
    ),
    CHECKPOINT_REASSESS_MISSIONS_DAMAGED: CheckpointSchema(
        CHECKPOINT_REASSESS_MISSIONS_DAMAGED,
        ACTION_REASSESS_MISSIONS_DAMAGED,
        "reassess_control_sea_missions_damaged_ship",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "missions",
        ),
    ),
    CHECKPOINT_AI_NAVAL_DEVELOPMENT: CheckpointSchema(
        CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        ACTION_AI_NAVAL_DEVELOPMENT,
        "ai_naval_industry_development",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "missions",
            "development",
        ),
    ),
    CHECKPOINT_SECOND_TURN_SEQUENCE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_SEQUENCE,
        ACTION_SECOND_TURN_SEQUENCE,
        "second_turn_sequence",
        (
            "stops",
            "economic_turn",
        ),
    ),
    CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE: CheckpointSchema(
        CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        ACTION_CONSECUTIVE_TURN_SEQUENCE,
        "consecutive_turn_sequence",
        (
            "stops",
            "economic_turns",
        ),
    ),
    CHECKPOINT_CHECK_TECH_ADVANCES: CheckpointSchema(
        CHECKPOINT_CHECK_TECH_ADVANCES,
        ACTION_CHECK_TECH_ADVANCES,
        "check_technology_advances",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "technology",
        ),
    ),
    CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE: CheckpointSchema(
        CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_ships_without_orders",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
}


_RESOURCE_NAMES = (
    "cotton", "wool", "timber", "coal", "iron", "horses", "oil", "food",
    "fabric", "lumber", "paper", "steel", "fuel", "clothing", "furniture",
    "hardware", "arms", "grain", "fruit", "fish", "livestock", "gems", "gold",
)


_DIPLOMACY_POLICY_NAMES = {
    0x12D: "join_empire",
    0x12E: "alliance",
    0x12F: "non_aggression_pact",
    0x130: "peace_treaty",
    0x131: "declare_war",
    0x132: "join_empire_with_war_entanglements",
    0x133: "build_consulate",
    0x134: "build_embassy",
}


def _native_captures(result: Mapping[str, Any]) -> Mapping[str, Any]:
    captures = result.get("captures")
    if not isinstance(captures, Mapping):
        captures_path = result.get("captures_path")
        if isinstance(captures_path, str) and captures_path:
            from pathlib import Path

            from tools.runtime.protocol import load_captures

            captures = load_captures(
                dict(result),
                Path(captures_path) if Path(captures_path).is_absolute() else Path("."),
            )
        else:
            captures = None
    return _require_mapping(captures, "native captures")


def _diplomacy_policy_name(code: Any, label: str) -> str | None:
    value = _require_int(code, label)
    if value == -1:
        return None
    name = _DIPLOMACY_POLICY_NAMES.get(value)
    if name is None:
        raise ValueError(f"{label} has no semantic representation: {value:#x}")
    return name


def _diplomacy_grant(entry: Any, label: str) -> dict[str, Any] | None:
    value = _require_int(entry, label)
    if value == -1:
        return None
    if value < -1:
        raise ValueError(f"{label} is below the -1 sentinel: {value}")
    return {"amount": value & 0x3FFF, "recurring": (value & 0x4000) != 0}


def normalize_native_diplomacy_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_DIPLOMACY_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable diplomacy-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    diplomacy = _require_mapping(ephemeral.get("diplomacy"), "native ephemeral diplomacy")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_DIPLOMACY_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "last_processed_nation": ephemeral.get("last_processed_nation"),
        "diplomacy": diplomacy,
    }


def normalize_retail_diplomacy_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_DIPLOMACY_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB diplomacy capture to the same stable schema."""
    nations_raw = raw.get("diplomacy_nations")
    if not isinstance(nations_raw, list):
        raise ValueError("retail diplomacy_nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"retail diplomacy nation {slot}")
        policies_raw = _require_int_list(
            nation_map.get("policies"), f"retail policies[{slot}]"
        )
        grants_raw = _require_int_list(
            nation_map.get("grants"), f"retail grants[{slot}]"
        )
        nations.append(
            {
                "treasury": _require_int(
                    nation_map.get("treasury"), f"retail treasury[{slot}]"
                ),
                "policies": [
                    _diplomacy_policy_name(code, f"retail policies[{slot}][{index}]")
                    for index, code in enumerate(policies_raw)
                ],
                "grants": [
                    _diplomacy_grant(entry, f"retail grants[{slot}][{index}]")
                    for index, entry in enumerate(grants_raw)
                ],
                "proposals": _diplomacy_proposals(
                    nation_map.get("proposals"), f"retail proposals[{slot}]"
                ),
                "turn_events": _diplomacy_records(
                    nation_map.get("turn_events"), f"retail turn_events[{slot}]"
                ),
            }
        )
    last_processed = raw.get("last_processed_nation")
    if last_processed == -1:
        last_processed = None
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_DIPLOMACY_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "last_processed_nation": last_processed,
        "diplomacy": {"nations": nations},
    }


def _diplomacy_proposals(records: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} must be an array")
    normalized = []
    for index, record in enumerate(records):
        record_map = _require_mapping(record, f"{label}[{index}]")
        normalized.append(
            {
                "source": _require_int(
                    record_map.get("source"), f"{label}[{index}].source"
                ),
                "policy": _diplomacy_policy_name(
                    record_map.get("code"), f"{label}[{index}].policy"
                ),
            }
        )
    return normalized


def normalize_native_trade_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_TRADE_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable trade-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    trade = _require_mapping(ephemeral.get("trade"), "native ephemeral trade")
    for row in _require_mapping(
        trade.get("market"), "native trade.market"
    ).get("rows", {}).values():
        if isinstance(row, Mapping) and "adjusted_offer_count" in row:
            row["adjusted_offer_count"] = float(row["adjusted_offer_count"])
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_TRADE_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "last_processed_nation": ephemeral.get("last_processed_nation"),
        "trade": trade,
    }


_TRADE_NATION_INT_FIELDS = (
    "treasury",
    "available_merchant",
    "merchant_capacity",
    "transport_capacity",
    "reserved_transport",
    "unfilled_trade_offer_count",
)

_TRADE_NATION_ARRAY_FIELDS = (
    "item_potentials",
    "remembered_trade_offers",
    "purchased_items",
    "transported_items",
    "unfilled_trade_turns",
    "city_stocks",
)


def normalize_retail_trade_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_TRADE_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB trade capture to the same stable schema."""
    rows_raw = raw.get("market_rows")
    if not isinstance(rows_raw, list) or len(rows_raw) != 17:
        raise ValueError("retail market_rows must hold the 17 priced categories")
    rows: dict[str, Any] = {}
    for index, row in enumerate(rows_raw):
        row_map = _require_mapping(row, f"retail market row {index}")
        rows[_RESOURCE_NAMES[index]] = {
            "previous_price": _require_int(
                row_map.get("previous_price"), f"retail previous_price[{index}]"
            ),
            "price": _require_int(row_map.get("price"), f"retail price[{index}]"),
            "base_price": _require_int(
                row_map.get("base_price"), f"retail base_price[{index}]"
            ),
            "request_count": _require_int(
                row_map.get("request_count"), f"retail request_count[{index}]"
            ),
            "offer_count": _require_int(
                row_map.get("offer_count"), f"retail offer_count[{index}]"
            ),
            "amount_offered": _require_int(
                row_map.get("amount_offered"), f"retail amount_offered[{index}]"
            ),
            "adjusted_offer_count": float(
                _require_number(
                    row_map.get("adjusted_offer_count"),
                    f"retail adjusted_offer_count[{index}]",
                )
            ),
            "current_offer_by_nation": _require_int_list(
                row_map.get("current_offer_by_nation"),
                f"retail current_offer_by_nation[{index}]",
            ),
            "maximum_offer_by_nation": _require_int_list(
                row_map.get("maximum_offer_by_nation"),
                f"retail maximum_offer_by_nation[{index}]",
            ),
        }
    nations_raw = raw.get("trade_nations")
    if not isinstance(nations_raw, list):
        raise ValueError("retail trade_nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"retail trade nation {slot}")
        entry: dict[str, Any] = {
            field: _require_int(
                nation_map.get(field), f"retail {field}[{slot}]"
            )
            for field in _TRADE_NATION_INT_FIELDS
        }
        for field in _TRADE_NATION_ARRAY_FIELDS:
            value = nation_map.get(field)
            entry[field] = (
                None
                if value is None
                else _require_int_list(value, f"retail {field}[{slot}]")
            )
        nations.append(entry)
    last_processed = raw.get("last_processed_nation")
    if last_processed == -1:
        last_processed = None
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_TRADE_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "last_processed_nation": last_processed,
        "trade": {"market": {"rows": rows}, "nations": nations},
    }


_CITY_NATION_INT_FIELDS = ("treasury", "reserved_transport")

_CITY_NATION_ARRAY_FIELDS = (
    "pending_actions",
    "item_potentials",
    "transported_items",
    "purchased_items",
    "production_orders",
    "production_accum",
    "production_flags",
    "city_stocks",
)

_CITY_REGION_INT_FIELDS = (
    "region_id",
    "development_stage",
    "last_turn_tick",
    "city_score",
    "linked_tile",
    "linked_dev_class",
    "linked_edge0",
    "linked_edge1",
)


def _city_transport_nations(raw_nations: Any, label: str) -> list[Any]:
    if not isinstance(raw_nations, list):
        raise ValueError(f"{label} must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(raw_nations):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}[{slot}]")
        entry: dict[str, Any] = {
            field: _require_int(
                nation_map.get(field), f"{label}[{slot}].{field}"
            )
            for field in _CITY_NATION_INT_FIELDS
        }
        for field in _CITY_NATION_ARRAY_FIELDS:
            value = nation_map.get(field)
            entry[field] = (
                None
                if value is None
                else _require_int_list(value, f"{label}[{slot}].{field}")
            )
        nations.append(entry)
    return nations


def _city_transport_regions(raw_regions: Any, label: str) -> list[Any]:
    if not isinstance(raw_regions, list):
        raise ValueError(f"{label} must be an array")
    regions: list[Any] = []
    for index, region in enumerate(raw_regions):
        region_map = _require_mapping(region, f"{label}[{index}]")
        entry: dict[str, Any] = {}
        for field in _CITY_REGION_INT_FIELDS:
            value = region_map.get(field)
            entry[field] = (
                None
                if value is None
                else _require_int(value, f"{label}[{index}].{field}")
            )
        entry["dev_counts"] = _require_int_list(
            region_map.get("dev_counts"), f"{label}[{index}].dev_counts"
        )
        regions.append(entry)
    return regions


def _city_transport_ephemeral(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    return {
        "nations": _city_transport_nations(raw.get("nations"), f"{label}.nations"),
        "regions": _city_transport_regions(raw.get("regions"), f"{label}.regions"),
    }


def normalize_native_city_transport_phase(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native driver result to the stable city+transport schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    city_transport = _require_mapping(
        ephemeral.get("city_transport"), "native ephemeral city_transport"
    )
    return {
        "checkpoint_id": CHECKPOINT_CITY_TRANSPORT_PHASE,
        "action_id": ACTION_CITY_TRANSPORT_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "city_transport": _city_transport_ephemeral(
            city_transport, "native city_transport"
        ),
    }


def normalize_retail_city_transport_phase(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a retail GDB city+transport capture to the same schema."""
    return {
        "checkpoint_id": CHECKPOINT_CITY_TRANSPORT_PHASE,
        "action_id": ACTION_CITY_TRANSPORT_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "city_transport": _city_transport_ephemeral(
            _require_mapping(
                raw.get("city_transport"), "retail city_transport"
            ),
            "retail city_transport",
        ),
    }


_CIVILIAN_UNIT_INT_FIELDS = (
    "tile",
    "kind",
    "order",
    "target",
    "owner",
    "remaining_turns",
    "completion_marker",
)

_CIVILIAN_NATION_INT_FIELDS = ("treasury", "town_count")


def _civilians_ephemeral(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    units_raw = raw.get("units")
    if not isinstance(units_raw, list):
        raise ValueError(f"{label}.units must be an array")
    units: list[Any] = []
    for index, unit in enumerate(units_raw):
        unit_map = _require_mapping(unit, f"{label}.units[{index}]")
        units.append(
            {
                field: _require_int(
                    unit_map.get(field), f"{label}.units[{index}].{field}"
                )
                for field in _CIVILIAN_UNIT_INT_FIELDS
            }
        )
    nations_raw = raw.get("nations")
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label}.nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}.nations[{slot}]")
        entry: dict[str, Any] = {
            field: _require_int(
                nation_map.get(field), f"{label}.nations[{slot}].{field}"
            )
            for field in _CIVILIAN_NATION_INT_FIELDS
        }
        stocks = nation_map.get("city_stocks")
        entry["city_stocks"] = (
            None
            if stocks is None
            else _require_int_list(stocks, f"{label}.nations[{slot}].city_stocks")
        )
        nations.append(entry)
    return {"units": units, "nations": nations}


def normalize_native_civilians_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_CIVILIANS_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable civilians-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    civilians = _require_mapping(
        ephemeral.get("civilians"), "native ephemeral civilians"
    )
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_CIVILIANS_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "civilians": _civilians_ephemeral(civilians, "native civilians"),
    }


def normalize_retail_civilians_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_CIVILIANS_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB civilians capture to the same schema."""
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_CIVILIANS_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "civilians": _civilians_ephemeral(
            _require_mapping(raw.get("civilians"), "retail civilians"),
            "retail civilians",
        ),
    }


_MILITARY_UNIT_INT_FIELDS = (
    "kind",
    "tile",
    "order",
    "target",
    "owner",
    "strength",
    "experience",
    "battle_flags",
)

_MILITARY_SHIP_INT_FIELDS = (
    "type",
    "nation",
    "strength",
    "experience",
    "zone",
)

_MILITARY_TASK_FORCE_INT_FIELDS = (
    "nation",
    "aggression",
    "ship_orders",
    "zone",
    "defeated",
    "child_count",
)


def _military_ephemeral(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    nations_raw = raw.get("nations")
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label}.nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}.nations[{slot}]")
        units_raw = nation_map.get("units")
        if not isinstance(units_raw, list):
            raise ValueError(f"{label}.nations[{slot}].units must be an array")
        units: list[Any] = []
        for index, unit in enumerate(units_raw):
            unit_map = _require_mapping(
                unit, f"{label}.nations[{slot}].units[{index}]"
            )
            units.append(
                {
                    field: _require_int(
                        unit_map.get(field),
                        f"{label}.nations[{slot}].units[{index}].{field}",
                    )
                    for field in _MILITARY_UNIT_INT_FIELDS
                }
            )
        nations.append(
            {
                "treasury": _require_int(
                    nation_map.get("treasury"),
                    f"{label}.nations[{slot}].treasury",
                ),
                "military_expenses": _require_int(
                    nation_map.get("military_expenses"),
                    f"{label}.nations[{slot}].military_expenses",
                ),
                "units": units,
            }
        )
    ships_raw = raw.get("ships")
    if not isinstance(ships_raw, list):
        raise ValueError(f"{label}.ships must be an array")
    ships: list[Any] = []
    for index, ship in enumerate(ships_raw):
        ship_map = _require_mapping(ship, f"{label}.ships[{index}]")
        ships.append(
            {
                field: _require_int(
                    ship_map.get(field), f"{label}.ships[{index}].{field}"
                )
                for field in _MILITARY_SHIP_INT_FIELDS
            }
        )
    forces_raw = raw.get("task_forces")
    if not isinstance(forces_raw, list):
        raise ValueError(f"{label}.task_forces must be an array")
    task_forces: list[Any] = []
    for index, force in enumerate(forces_raw):
        force_map = _require_mapping(force, f"{label}.task_forces[{index}]")
        task_forces.append(
            {
                field: _require_int(
                    force_map.get(field),
                    f"{label}.task_forces[{index}].{field}",
                )
                for field in _MILITARY_TASK_FORCE_INT_FIELDS
            }
        )
    normalized = {
        "nations": nations,
        "ships": ships,
        "task_forces": task_forces,
    }
    owners_raw = raw.get("province_owners")
    if owners_raw is not None:
        if not isinstance(owners_raw, list):
            raise ValueError(f"{label}.province_owners must be an array")
        normalized["province_owners"] = [
            _require_int(owner, f"{label}.province_owners[{index}]")
            for index, owner in enumerate(owners_raw)
        ]
    battle_raw = raw.get("land_battle")
    if battle_raw is not None:
        battle_map = _require_mapping(battle_raw, f"{label}.land_battle")
        created = battle_map.get("created")
        if not isinstance(created, bool):
            raise ValueError(f"{label}.land_battle.created must be a boolean")
        normalized["land_battle"] = {
            "created": created,
            "outcome": _require_int(
                battle_map.get("outcome"), f"{label}.land_battle.outcome"
            ),
        }
    return normalized


def normalize_native_military_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_MILITARY_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable military-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    military = _require_mapping(
        ephemeral.get("military"), "native ephemeral military"
    )
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_MILITARY_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "military": _military_ephemeral(military, "native military"),
    }


def normalize_retail_military_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_MILITARY_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB military capture to the same schema."""
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_MILITARY_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "military": _military_ephemeral(
            _require_mapping(raw.get("military"), "retail military"),
            "retail military",
        ),
    }


_MILITARY_CLEANUP_METRIC_KEYS = (
    "queue_divergence",
    "mobile_score",
    "mobile_divergence",
    "combined_divergence",
    "weighted_military",
    "expansion_pressure",
    "unit_divergence",
    "mission_pressure",
)


def _military_cleanup_ephemeral(raw: Any, label: str) -> dict[str, Any]:
    mapping = _require_mapping(raw, label)
    normalized = {
        "region_scores": _require_int_list(
            mapping.get("region_scores"), f"{label}.region_scores"
        ),
        "city_score_total": _require_int(
            mapping.get("city_score_total"), f"{label}.city_score_total"
        ),
    }
    for key in _MILITARY_CLEANUP_METRIC_KEYS:
        normalized[key] = _require_int_list(
            mapping.get(key), f"{label}.{key}"
        )
    return normalized


def normalize_native_military_cleanup(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
) -> dict[str, Any]:
    """Reduce a native driver result to the military-cleanup schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    cleanup = _require_mapping(
        ephemeral.get("military_cleanup"), "native ephemeral military_cleanup"
    )
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_MILITARY_CLEANUP,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "military_cleanup": _military_cleanup_ephemeral(
            cleanup, "native military_cleanup"
        ),
    }


def normalize_retail_military_cleanup(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
) -> dict[str, Any]:
    """Reduce a retail GDB military-cleanup capture to the same schema."""
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_MILITARY_CLEANUP,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "military_cleanup": _military_cleanup_ephemeral(
            _require_mapping(raw.get("military_cleanup"), "retail military_cleanup"),
            "retail military_cleanup",
        ),
    }


def _diplomacy_records(records: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} must be an array")
    normalized = []
    for index, record in enumerate(records):
        record_map = _require_mapping(record, f"{label}[{index}]")
        normalized.append(
            {
                "code": record_map.get("code"),
                "source": _require_int(
                    record_map.get("source"), f"{label}[{index}].source"
                ),
            }
        )
    return normalized


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _require_number(value: Any, label: str) -> "int | float":
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    return value


def _require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _require_int_list(value: Any, label: str) -> list[int]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in value
    ):
        raise ValueError(f"{label} must be an integer array")
    return value


_TURN_STATE_STOP_NAMES = {
    0x0E: "deal_book",
    0x12: "newspaper",
    0x05: "player_orders",
}


def normalize_native_second_turn_sequence(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native second-turn state-machine walk to its stop sequence."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    stops_raw = transition_result.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("native result stops must be an array")
    stops: list[str] = []
    for index, stop in enumerate(stops_raw):
        if not isinstance(stop, str):
            raise ValueError(f"native result stops[{index}] must be a string")
        stops.append(stop)
    return {
        "checkpoint_id": CHECKPOINT_SECOND_TURN_SEQUENCE,
        "action_id": ACTION_SECOND_TURN_SEQUENCE,
        "stops": stops,
        "economic_turn": _require_int(
            transition_result.get("economic_turn"), "native economic_turn"
        ),
    }


def normalize_native_consecutive_turn_sequence(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native 12-turn state-machine walk to stops + turn numbers."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    stops_raw = transition_result.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("native result stops must be an array")
    stops: list[str] = []
    for index, stop in enumerate(stops_raw):
        if not isinstance(stop, str):
            raise ValueError(f"native result stops[{index}] must be a string")
        stops.append(stop)
    return {
        "checkpoint_id": CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        "action_id": ACTION_CONSECUTIVE_TURN_SEQUENCE,
        "stops": stops,
        "economic_turns": _require_int_list(
            transition_result.get("economic_turns"), "native economic_turns"
        ),
    }


def normalize_retail_consecutive_turn_sequence(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail 12-turn state-machine walk to the same schema."""
    stops_raw = raw.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("retail stops must be an array")
    stops = []
    for index, code in enumerate(stops_raw):
        code = _require_int(code, f"retail stops[{index}]")
        name = _TURN_STATE_STOP_NAMES.get(code)
        if name is None:
            raise ValueError(f"retail stops[{index}] unknown state {code:#x}")
        stops.append(name)
    return {
        "checkpoint_id": CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        "action_id": ACTION_CONSECUTIVE_TURN_SEQUENCE,
        "stops": stops,
        "economic_turns": _require_int_list(
            raw.get("economic_turns"), "retail economic_turns"
        ),
    }


def normalize_native_recompute_metrics(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native metric case result payload to its float-bit arrays."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    normalized: dict[str, Any] = {
        "checkpoint_id": CHECKPOINT_RECOMPUTE_METRICS,
        "action_id": ACTION_RECOMPUTE_METRICS,
    }
    for key in _MILITARY_CLEANUP_METRIC_KEYS:
        normalized[key] = _require_int_list(
            transition_result.get(key), f"native result {key}"
        )
    return normalized


def normalize_retail_recompute_metrics(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail metric capture to the same float-bit arrays."""
    normalized = {
        "checkpoint_id": CHECKPOINT_RECOMPUTE_METRICS,
        "action_id": ACTION_RECOMPUTE_METRICS,
    }
    for key in _MILITARY_CLEANUP_METRIC_KEYS:
        normalized[key] = _require_int_list(raw.get(key), f"retail {key}")
    return normalized


def _mission_records(records: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} must be an array")
    normalized = []
    for index, record in enumerate(records):
        entry = _require_mapping(record, f"{label}[{index}]")
        mission = {
            "nation": _require_int(entry.get("nation"), f"{label}[{index}].nation"),
            "kind": entry.get("kind"),
            "nation_id": _require_int(
                entry.get("nation_id"), f"{label}[{index}].nation_id"
            ),
            "path_marker": _require_int(
                entry.get("path_marker"), f"{label}[{index}].path_marker"
            ),
            "state": _require_int(entry.get("state"), f"{label}[{index}].state"),
            "importance_bits": _require_int(
                entry.get("importance_bits"), f"{label}[{index}].importance_bits"
            ),
            "flag10": _require_int(
                entry.get("flag10"), f"{label}[{index}].flag10"
            ),
            "marker": _require_int(
                entry.get("marker"), f"{label}[{index}].marker"
            ),
        }
        if entry.get("navy_state") is not None:
            mission["target_zone"] = _require_int(
                entry.get("target_zone"), f"{label}[{index}].target_zone"
            )
            mission["resolved_port_zone"] = _require_int(
                entry.get("resolved_port_zone"),
                f"{label}[{index}].resolved_port_zone",
            )
            mission["navy_state"] = _require_int(
                entry.get("navy_state"), f"{label}[{index}].navy_state"
            )
            mission["has_orders"] = _require_bool(
                entry.get("has_orders"), f"{label}[{index}].has_orders"
            )
            mission["required_equipage_bits"] = _require_int_list(
                entry.get("required_equipage_bits"),
                f"{label}[{index}].required_equipage_bits",
            )
        normalized.append(mission)
    return normalized


def _mission_turn(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    return {
        "phase": _require_int(raw.get("phase"), f"{label}.phase"),
        "active": _require_int(
            raw.get("active_nation", raw.get("active")), f"{label}.active"
        ),
        "economic_turn": _require_int(
            raw.get("economic_turn"), f"{label}.economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), f"{label}.turn_flow_status_flags"
        ),
    }


def normalize_native_reassess_missions(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_REASSESS_MISSIONS,
) -> dict[str, Any]:
    """Reduce a native driver result to the mission-reassess schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_REASSESS_MISSIONS,
        "turn": _mission_turn(turn, "native turn"),
        "missions": _mission_records(
            ephemeral.get("missions"), "native missions"
        ),
    }


def normalize_retail_reassess_missions(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_REASSESS_MISSIONS,
) -> dict[str, Any]:
    """Reduce a retail GDB mission capture to the same schema."""
    turn = {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_REASSESS_MISSIONS,
        "turn": turn,
        "missions": _mission_records(raw.get("missions"), "retail missions"),
    }


def _development_records(raw: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    records = []
    for index, entry in enumerate(raw):
        entry = _require_mapping(entry, f"{label}[{index}]")
        records.append(
            {
                "nation": _require_int(
                    entry.get("nation"), f"{label}[{index}].nation"
                ),
                "order_ba": _require_int_list(
                    entry.get("order_ba"), f"{label}[{index}].order_ba"
                ),
                "order_dc": _require_int_list(
                    entry.get("order_dc"), f"{label}[{index}].order_dc"
                ),
                "queued_orders": _require_int_list(
                    entry.get("queued_orders"),
                    f"{label}[{index}].queued_orders",
                ),
            }
        )
    return records


def normalize_native_ai_naval_development(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a native driver result to the AI-development schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        "action_id": ACTION_AI_NAVAL_DEVELOPMENT,
        "turn": _mission_turn(turn, "native turn"),
        "missions": _mission_records(
            ephemeral.get("missions"), "native missions"
        ),
        "development": _development_records(
            ephemeral.get("development"), "native development"
        ),
    }


def normalize_retail_ai_naval_development(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a retail GDB AI-development capture to the same schema."""
    turn = {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }
    return {
        "checkpoint_id": CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        "action_id": ACTION_AI_NAVAL_DEVELOPMENT,
        "turn": turn,
        "missions": _mission_records(raw.get("missions"), "retail missions"),
        "development": _development_records(
            raw.get("development"), "retail development"
        ),
    }


def _technology_record(raw: Any, label: str) -> dict[str, Any]:
    entry = _require_mapping(raw, label)
    nations_raw = entry.get("nations")
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label}.nations must be an array")
    nations = []
    for index, nation in enumerate(nations_raw):
        nation = _require_mapping(nation, f"{label}.nations[{index}]")
        nations.append(
            {
                "nation": _require_int(
                    nation.get("nation"), f"{label}.nations[{index}].nation"
                ),
                "treasury": _require_int(
                    nation.get("treasury"),
                    f"{label}.nations[{index}].treasury",
                ),
                "tech_status": _require_int_list(
                    nation.get("tech_status"),
                    f"{label}.nations[{index}].tech_status",
                ),
                "completion_years": _require_int_list(
                    nation.get("completion_years"),
                    f"{label}.nations[{index}].completion_years",
                ),
                "abilities": _require_int_list(
                    nation.get("abilities"),
                    f"{label}.nations[{index}].abilities",
                ),
                "university": _require_int_list(
                    nation.get("university"),
                    f"{label}.nations[{index}].university",
                ),
            }
        )
    return {
        "marker": _require_int(entry.get("marker"), f"{label}.marker"),
        "prereq_primary": _require_int(
            entry.get("prereq_primary"), f"{label}.prereq_primary"
        ),
        "prereq_secondary": _require_int(
            entry.get("prereq_secondary"), f"{label}.prereq_secondary"
        ),
        "selector": _require_int(entry.get("selector"), f"{label}.selector"),
        "zone_index": _require_int(
            entry.get("zone_index"), f"{label}.zone_index"
        ),
        "unlock_flags": _require_int_list(
            entry.get("unlock_flags"), f"{label}.unlock_flags"
        ),
        "enabled_types": _require_int_list(
            entry.get("enabled_types"), f"{label}.enabled_types"
        ),
        "nations": nations,
    }


def normalize_native_check_technology_advances(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a native driver result to the technology-advance schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": CHECKPOINT_CHECK_TECH_ADVANCES,
        "action_id": ACTION_CHECK_TECH_ADVANCES,
        "turn": _mission_turn(turn, "native turn"),
        "technology": _technology_record(
            ephemeral.get("technology"), "native technology"
        ),
    }


def normalize_retail_check_technology_advances(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a retail GDB technology capture to the same schema."""
    turn = {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }
    return {
        "checkpoint_id": CHECKPOINT_CHECK_TECH_ADVANCES,
        "action_id": ACTION_CHECK_TECH_ADVANCES,
        "turn": turn,
        "technology": _technology_record(
            raw.get("technology"), "retail technology"
        ),
    }


def normalize_retail_second_turn_sequence(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail state-machine walk to the same stop sequence."""
    stops_raw = raw.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("retail stops must be an array")
    stops = []
    for index, code in enumerate(stops_raw):
        code = _require_int(code, f"retail stops[{index}]")
        name = _TURN_STATE_STOP_NAMES.get(code)
        if name is None:
            raise ValueError(f"retail stops[{index}] unknown state {code:#x}")
        stops.append(name)
    return {
        "checkpoint_id": CHECKPOINT_SECOND_TURN_SEQUENCE,
        "action_id": ACTION_SECOND_TURN_SEQUENCE,
        "stops": stops,
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
    }


def normalize_native_combined_map(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native driver result to the stable combined-map schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    map_state = _require_mapping(captures.get("map_state"), "native map_state")
    root_class = map_state.get("root_class")
    if root_class != "TMapUberPicture":
        raise ValueError(f"native active view is {root_class!r}, expected TMapUberPicture")
    return {
        "checkpoint_id": CHECKPOINT_COMBINED_MAP_READY,
        "action_id": ACTION_COMBINED_MAP_ENTRY,
        "turn_event": _require_int(map_state.get("turn_event"), "native turn_event"),
        "active_view": "strategic_map",
        "nation": {
            "active": _require_int(
                map_state.get("active_nation"), "native active_nation"
            ),
            "economic_turn": _require_int(
                map_state.get("economic_turn"), "native economic_turn"
            ),
        },
        "map": {
            "present": _require_bool(
                map_state.get("global_map"), "native global_map"
            ),
            "wrap": _require_int(map_state.get("wrap"), "native map wrap"),
        },
        "city_orders": {
            "city_present": _require_bool(
                map_state.get("city_present"), "native city_present"
            ),
            "production_orders": _require_int_list(
                map_state.get("production_orders"), "native production_orders"
            ),
            "production_flags": _require_int_list(
                map_state.get("production_flags"), "native production_flags"
            ),
        },
    }


def normalize_retail_combined_map(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a retail GDB capture to the same stable combined-map schema."""
    map_view_present = _require_bool(
        fields.get("combined_map_view_present"), "retail combined_map_view_present"
    )
    if not map_view_present:
        raise ValueError("retail combined map view is absent")
    return {
        "checkpoint_id": CHECKPOINT_COMBINED_MAP_READY,
        "action_id": ACTION_COMBINED_MAP_ENTRY,
        "turn_event": _require_int(fields.get("turn_event"), "retail turn_event"),
        "active_view": "strategic_map",
        "nation": {
            "active": _require_int(fields.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                fields.get("economic_turn"), "retail economic_turn"
            ),
        },
        "map": {
            "present": _require_bool(fields.get("map_present"), "retail map_present"),
            "wrap": _require_int(fields.get("map_wrap"), "retail map_wrap"),
        },
        "city_orders": {
            "city_present": _require_bool(
                fields.get("city_present"), "retail city_present"
            ),
            "production_orders": [
                _require_int(fields.get(f"production_order_{slot:02d}"),
                             f"retail production_order_{slot:02d}")
                for slot in range(16)
            ],
            "production_flags": [
                _require_int(fields.get(f"production_flag_{slot:02d}"),
                             f"retail production_flag_{slot:02d}")
                for slot in range(16)
            ],
        },
    }


def first_checkpoint_difference(left: Any, right: Any, path: str = "$") -> dict | None:
    """Return the first typed semantic difference with a JSON-style field path."""
    if type(left) is not type(right):
        return {"path": path, "kind": "type_mismatch", "retail": left, "recomp": right}
    if isinstance(left, dict):
        keys = list(left)
        keys.extend(key for key in right if key not in left)
        for key in keys:
            child_path = f"{path}.{key}"
            if key not in left:
                return {"path": child_path, "kind": "missing_retail", "recomp": right[key]}
            if key not in right:
                return {"path": child_path, "kind": "missing_recomp", "retail": left[key]}
            difference = first_checkpoint_difference(left[key], right[key], child_path)
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {
                "path": path,
                "kind": "length_mismatch",
                "retail": len(left),
                "recomp": len(right),
            }
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
            difference = first_checkpoint_difference(
                left_item, right_item, f"{path}[{index}]"
            )
            if difference is not None:
                return difference
        return None
    if left != right:
        return {"path": path, "kind": "value_mismatch", "retail": left, "recomp": right}
    return None


def validate_checkpoint(observation: Mapping[str, Any]) -> None:
    checkpoint_id = observation.get("checkpoint_id")
    schema = SCHEMAS.get(checkpoint_id)
    if schema is None:
        raise ValueError(f"unknown checkpoint_id {checkpoint_id!r}")
    if observation.get("action_id") != schema.action_id:
        raise ValueError(
            f"checkpoint {checkpoint_id!r} requires action_id {schema.action_id!r}"
        )
    for path in schema.required_paths:
        current: Any = observation
        for component in path.split("."):
            if not isinstance(current, Mapping) or component not in current:
                raise ValueError(f"checkpoint {checkpoint_id!r} is missing {path}")
            current = current[component]
