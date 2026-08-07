"""Versioned parsing and validation for the native runtime JSON protocol."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.runtime.catalog import EVIDENCE_KINDS


FORMAT_VERSION = 1
GAME_SNAPSHOT_SCHEMA = "imperialism.game_snapshot.v1"
GAME_SNAPSHOT_SECTIONS = ("metadata", "rng", "world", "nations", "economy")
HASH_PATTERN = re.compile(r"[0-9a-f]{8}")


def read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def validate_result(result: dict[str, Any], expected_name: str, expected_seed: int) -> None:
    if result.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"unsupported runtime result format_version {result.get('format_version')!r}")
    if result.get("name") != expected_name:
        raise ValueError(f"driver ran {result.get('name')!r}, requested {expected_name!r}")
    if result.get("seed") != expected_seed:
        raise ValueError(f"driver ran with seed {result.get('seed')}, requested {expected_seed}")
    if result.get("status") not in {"passed", "failed", "skipped"}:
        raise ValueError(f"invalid runtime result status {result.get('status')!r}")
    evidence_kind = result.get("evidence_kind")
    if evidence_kind is not None and evidence_kind not in EVIDENCE_KINDS:
        raise ValueError(f"invalid evidence_kind {evidence_kind!r}")
    snapshot = result.get("game_snapshot")
    if snapshot is not None:
        validate_game_snapshot(snapshot)


def validate_game_snapshot(snapshot: object) -> None:
    if not isinstance(snapshot, dict):
        raise ValueError("game_snapshot must be an object")
    if snapshot.get("schema") != GAME_SNAPSHOT_SCHEMA:
        raise ValueError(f"unsupported game_snapshot schema {snapshot.get('schema')!r}")
    if snapshot.get("sections") != list(GAME_SNAPSHOT_SECTIONS):
        raise ValueError(f"invalid game_snapshot sections {snapshot.get('sections')!r}")
    hashes = snapshot.get("hashes")
    if not isinstance(hashes, dict):
        raise ValueError("game_snapshot hashes must be an object")
    for name in (*GAME_SNAPSHOT_SECTIONS, "state"):
        value = hashes.get(name)
        if not isinstance(value, str) or HASH_PATTERN.fullmatch(value) is None:
            raise ValueError(f"invalid game_snapshot hash for {name}")
    for name in GAME_SNAPSHOT_SECTIONS:
        if not isinstance(snapshot.get(name), dict):
            raise ValueError(f"game_snapshot {name} must be an object")
    world = snapshot["world"]
    width = world.get("width")
    height = world.get("height")
    tiles = world.get("tiles")
    if width != 108 or height != 60 or not isinstance(tiles, list):
        raise ValueError("game_snapshot world must contain the 108x60 tile grid")
    if len(tiles) != width * height:
        raise ValueError("game_snapshot world tile count does not match its dimensions")
    if any(
        not isinstance(tile, list)
        or len(tile) != 10
        or any(isinstance(value, bool) or not isinstance(value, int) for value in tile)
        for tile in tiles
    ):
        raise ValueError("game_snapshot world tile rows must contain ten integers")

    records = snapshot["nations"].get("records")
    if not isinstance(records, list) or len(records) != 23:
        raise ValueError("game_snapshot nations must contain 23 records")
    for slot, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("game_snapshot nation records must be objects")
        if record.get("slot") != slot:
            raise ValueError("game_snapshot nation records must be in slot order")
        expected_kind = "major" if slot < 7 else "minor"
        if record.get("kind") != expected_kind or not isinstance(record.get("present"), bool):
            raise ValueError("game_snapshot nation record identity is invalid")
        if record["present"] and slot < 7 and not isinstance(record.get("major"), dict):
            raise ValueError("game_snapshot present major nations must contain major state")
        if record["present"]:
            _require_integer_array(record, "need_level_by_nation", 23)
        if record["present"] and slot < 7:
            major = record["major"]
            for field in (
                "diplomacy_policy_by_nation",
                "diplomacy_grant_by_nation",
                "need_current_by_type",
                "need_target_by_type",
                "relation_delta_current",
                "purchased_items_by_resource",
                "item_potentials",
                "unfilled_trade_turns_by_resource",
                "transported_items_by_resource",
                "remembered_trade_offers_by_resource",
                "candidate_nation_flags",
                "colony_boycott_flags",
            ):
                _require_integer_array(major, field, 23)
            _require_integer_array(major, "capacities", 4)
            _require_integer_array(major, "aid_allocation_matrix", 0x170)
            _require_integer_array(major, "pending_action_status", 13)
            _require_integer_array(major, "pending_action_payload_by_action", 13)

    cities = snapshot["economy"].get("cities")
    if not isinstance(cities, list) or len(cities) != 7:
        raise ValueError("game_snapshot economy must contain seven city records")
    for slot, city in enumerate(cities):
        if not isinstance(city, dict):
            raise ValueError("game_snapshot city records must be objects")
        if city.get("nation") != slot or not isinstance(city.get("present"), bool):
            raise ValueError("game_snapshot city record identity is invalid")
        if city["present"] and not isinstance(city.get("population"), dict):
            raise ValueError("game_snapshot present cities must contain population state")
        if city["present"]:
            for field, count in (
                ("metrics_0e", 30),
                ("metrics_4a", 9),
                ("order_count_by_type", 14),
                ("reserved_by_type", 23),
                ("stock_by_type", 23),
                ("production_orders", 16),
                ("production_accum", 16),
                ("production_flags", 16),
                ("production_current", 16),
                ("production_progress", 16),
                ("unmet_resource_retries", 23),
                ("consumed_production_input_by_type", 23),
            ):
                _require_integer_array(city, field, count)
            population = city["population"]
            _require_integer_array(population, "predicted_need_by_resource", 23)
            for field in ("baseline_labor", "production_labor", "pending_labor_delta"):
                if population.get(field) is not None:
                    _require_integer_array(population, field, 3)


def _require_integer_array(container: dict[str, Any], field: str, count: int) -> None:
    values = container.get(field)
    if (
        not isinstance(values, list)
        or len(values) != count
        or any(isinstance(value, bool) or not isinstance(value, int) for value in values)
    ):
        raise ValueError(f"game_snapshot {field} must contain {count} integers")
