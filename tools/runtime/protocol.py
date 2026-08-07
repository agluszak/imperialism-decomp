"""Versioned parsing and validation for the native runtime JSON protocol."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.runtime.catalog import EVIDENCE_KINDS


FORMAT_VERSION = 1
GAME_SNAPSHOT_SCHEMA = "imperialism.game_snapshot.v1"
GENERATED_WORLD_SCHEMA = "imperialism.generated_world.v1"
GENERATED_WORLD_TILE_FIELDS = (
    "terrain_kind",
    "sprite_variant",
    "river_sprite_code",
    "former_owner_nation",
    "owner_nation",
    "region_subtype",
    "adjacency_bits",
    "owner_border_mask",
    "city_border_mask",
    "water_adjacency_mask",
    "adjacency_mask_a",
    "adjacency_mask_b",
    "development_class_nibbles",
    "pending_development_flag",
    "recruit_search_visited",
    "per_tile_visited_flag",
    "marker_slot_index",
    "resource_edge_0",
    "resource_edge_1",
    "gate_flag",
    "province_index",
    "tile_action_state",
    "rail_flags",
    "secondary_owner_nation",
    "tile_action_ordinal",
    "active_flags",
)
GENERATED_WORLD_BORDER_LINK_FIELDS = (
    "x0",
    "y0",
    "x1",
    "y1",
    "coord0",
    "coord1",
    "region_a",
    "region_b",
    "angle",
    "wrap",
)
GAME_SNAPSHOT_SECTIONS = (
    "metadata",
    "rng",
    "world",
    "nations",
    "economy",
    "military",
    "missions",
    "pending",
)
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
    generated_world = result.get("generated_world")
    if generated_world is not None:
        validate_generated_world(generated_world)


def validate_generated_world(snapshot: object) -> None:
    if not isinstance(snapshot, dict):
        raise ValueError("generated_world must be an object")
    _require_exact_keys(
        snapshot,
        {
            "schema",
            "tile_fields",
            "border_link_fields",
            "map",
            "rng",
            "tiles",
            "provinces",
            "ocean_context_array_count",
            "sea_region_count",
            "sea_regions",
            "route_count",
            "routes",
            "border_links",
        },
        "generated_world",
    )
    if snapshot["schema"] != GENERATED_WORLD_SCHEMA:
        raise ValueError(f"unsupported generated_world schema {snapshot['schema']!r}")
    if snapshot["tile_fields"] != list(GENERATED_WORLD_TILE_FIELDS):
        raise ValueError("generated_world tile_fields do not match the v1 schema")
    if snapshot["border_link_fields"] != list(GENERATED_WORLD_BORDER_LINK_FIELDS):
        raise ValueError("generated_world border_link_fields do not match the v1 schema")

    map_state = snapshot["map"]
    if not isinstance(map_state, dict):
        raise ValueError("generated_world map must be an object")
    _require_exact_keys(
        map_state,
        {
            "width",
            "height",
            "scenario_tag",
            "retail_topology_byte",
            "wraps_horizontally",
            "strategic_map_palette_preview_ready",
            "map_manager_ready",
            "map_data_ready",
            "tile_search_flag",
            "city_score_total",
            "pending_river_mouth_tile",
        },
        "generated_world map",
    )
    if map_state["width"] != 108 or map_state["height"] != 60:
        raise ValueError("generated_world map must be 108x60")
    if not isinstance(map_state["scenario_tag"], str):
        raise ValueError("generated_world scenario_tag must be a string")
    _require_int_range(map_state["retail_topology_byte"], -128, 127, "retail_topology_byte")
    if not isinstance(map_state["wraps_horizontally"], bool):
        raise ValueError("generated_world wraps_horizontally must be a boolean")
    if map_state["wraps_horizontally"] != (map_state["retail_topology_byte"] == 0):
        raise ValueError("generated_world topology byte has invalid retail wrap semantics")
    for field in (
        "strategic_map_palette_preview_ready",
        "map_data_ready",
        "tile_search_flag",
    ):
        _require_int_range(map_state[field], 0, 255, f"generated_world map {field}")
    for field in ("map_manager_ready", "city_score_total", "pending_river_mouth_tile"):
        _require_integer(map_state[field], f"generated_world map {field}")

    rng = snapshot["rng"]
    if not isinstance(rng, dict):
        raise ValueError("generated_world rng must be an object")
    _require_exact_keys(
        rng,
        {"runtime_seed", "crt_rand_state", "map_generation_lcg", "zone_status_lcg"},
        "generated_world rng",
    )
    for field, value in rng.items():
        _require_int_range(value, 0, 0xFFFFFFFF, f"generated_world rng {field}")

    tiles = snapshot["tiles"]
    if not isinstance(tiles, list) or len(tiles) != 108 * 60:
        raise ValueError("generated_world tiles must contain the 108x60 tile grid")
    _require_integer_rows(tiles, len(GENERATED_WORLD_TILE_FIELDS), "generated_world tiles")

    provinces = snapshot["provinces"]
    if not isinstance(provinces, list) or len(provinces) != 0x180:
        raise ValueError("generated_world provinces must contain 384 records")
    province_keys = {
        "index",
        "owner_nation",
        "former_owner_nation",
        "development_stage",
        "fort_level",
        "city_tile",
        "last_turn_tick",
        "adjacent_region_count",
        "adjacent_region_ids",
        "adjacent_region_anchor_tiles",
        "linked_region_count",
        "secondary_neighbor_tile",
        "primary_neighbor_tile",
        "linked_tile_indices",
        "resource_development_counts",
        "city_score",
        "navy_order_reachable",
        "explored_by_nation_mask",
        "resource_presence_mask",
        "region_class",
        "city_name",
    }
    province_arrays = (
        ("adjacent_region_ids", 12),
        ("adjacent_region_anchor_tiles", 12),
        ("linked_tile_indices", 32),
        ("resource_development_counts", 10),
    )
    for index, province in enumerate(provinces):
        if not isinstance(province, dict):
            raise ValueError("generated_world province records must be objects")
        _require_exact_keys(province, province_keys, "generated_world province")
        if province["index"] != index:
            raise ValueError("generated_world provinces must be in index order")
        if not isinstance(province["city_name"], str):
            raise ValueError("generated_world province city_name must be a string")
        for field, count in province_arrays:
            _require_integer_array_for(province, field, count, "generated_world province")
        for field in province_keys - {"city_name", *(field for field, _ in province_arrays)}:
            _require_integer(province[field], f"generated_world province {field}")

    for field in ("ocean_context_array_count", "sea_region_count", "route_count"):
        _require_integer(snapshot[field], f"generated_world {field}")
    sea_regions = snapshot["sea_regions"]
    if not isinstance(sea_regions, list) or len(sea_regions) != snapshot["sea_region_count"]:
        raise ValueError("generated_world sea_region_count must match sea_regions")
    sea_region_keys = {
        "index",
        "kind",
        "context_ordinal",
        "status_code",
        "display_name",
        "tile_or_terrain_id",
        "nation_key_mask",
        "seed_nation_id",
        "active_tile",
        "distance_level",
        "port_tile",
        "primary_neighbors",
        "secondary_neighbors",
    }
    for index, region in enumerate(sea_regions):
        if not isinstance(region, dict):
            raise ValueError("generated_world sea regions must be objects")
        _require_exact_keys(region, sea_region_keys, "generated_world sea region")
        if region["index"] != index or region["kind"] not in {"zone", "port"}:
            raise ValueError("generated_world sea region identity is invalid")
        if not isinstance(region["display_name"], str):
            raise ValueError("generated_world sea region display_name must be a string")
        for field in ("primary_neighbors", "secondary_neighbors"):
            values = region[field]
            if not isinstance(values, list) or any(not _is_integer(value) for value in values):
                raise ValueError(f"generated_world sea region {field} must contain integers")
        for field in sea_region_keys - {
            "kind",
            "display_name",
            "primary_neighbors",
            "secondary_neighbors",
        }:
            _require_integer(region[field], f"generated_world sea region {field}")

    routes = snapshot["routes"]
    if not isinstance(routes, list) or len(routes) != snapshot["route_count"]:
        raise ValueError("generated_world route_count must match routes")
    _require_integer_rows(routes, 4, "generated_world routes")
    border_links = snapshot["border_links"]
    if not isinstance(border_links, list):
        raise ValueError("generated_world border_links must be an array")
    _require_integer_rows(
        border_links, len(GENERATED_WORLD_BORDER_LINK_FIELDS), "generated_world border_links"
    )


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

    missions = snapshot["missions"].get("records")
    if not isinstance(missions, list):
        raise ValueError("game_snapshot missions must contain ordered records")
    for index, mission in enumerate(missions):
        if (
            not isinstance(mission, dict)
            or mission.get("index") != index
            or not isinstance(mission.get("class"), str)
        ):
            raise ValueError("game_snapshot mission identity is invalid")

    pending_nations = snapshot["pending"].get("nations")
    if not isinstance(pending_nations, list) or len(pending_nations) != 7:
        raise ValueError("game_snapshot pending work must contain seven nation records")
    if any(
        not isinstance(record, dict) or record.get("nation") != nation
        for nation, record in enumerate(pending_nations)
    ):
        raise ValueError("game_snapshot pending nation identity is invalid")

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
            special_balance = major.get("special_resource_trade_balance")
            if isinstance(special_balance, bool) or not isinstance(special_balance, int):
                raise ValueError(
                    "game_snapshot major nation special-resource trade balance must be an integer"
                )
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

    military = snapshot["military"]
    for field in ("units", "ships", "task_forces"):
        if not isinstance(military.get(field), list):
            raise ValueError(f"game_snapshot military {field} must be an array")
    for unit in military["units"]:
        if not isinstance(unit, dict):
            raise ValueError("game_snapshot military units must be objects")
        _require_integer_array(unit, "order_target_tiles", 3)
        _require_integer_array(unit, "order_target_mirrors", 3)
    for index, ship in enumerate(military["ships"]):
        if not isinstance(ship, dict) or ship.get("index") != index:
            raise ValueError("game_snapshot ships must be objects in index order")
    for index, force in enumerate(military["task_forces"]):
        if not isinstance(force, dict) or force.get("index") != index:
            raise ValueError("game_snapshot task forces must be objects in index order")
        _require_integer_array(force, "ship_counts", 4)
        ships = force.get("ships")
        if (
            not isinstance(ships, list)
            or any(
                not isinstance(child, list)
                or len(child) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) for value in child)
                for child in ships
            )
        ):
            raise ValueError("game_snapshot task-force ships must be integer pairs")


def _require_integer_array(container: dict[str, Any], field: str, count: int) -> None:
    _require_integer_array_for(container, field, count, "game_snapshot")


def _require_integer_array_for(
    container: dict[str, Any], field: str, count: int, context: str
) -> None:
    values = container.get(field)
    if (
        not isinstance(values, list)
        or len(values) != count
        or any(not _is_integer(value) for value in values)
    ):
        raise ValueError(f"{context} {field} must contain {count} integers")


def _require_integer_rows(rows: list[object], width: int, context: str) -> None:
    if any(
        not isinstance(row, list)
        or len(row) != width
        or any(not _is_integer(value) for value in row)
        for row in rows
    ):
        raise ValueError(f"{context} rows must contain {width} integers")


def _require_exact_keys(container: dict[str, Any], keys: set[str], context: str) -> None:
    if set(container) != keys:
        raise ValueError(f"{context} fields do not match the v1 schema")


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_integer(value: object, context: str) -> None:
    if not _is_integer(value):
        raise ValueError(f"{context} must be an integer")


def _require_int_range(value: object, minimum: int, maximum: int, context: str) -> None:
    _require_integer(value, context)
    assert isinstance(value, int)
    if value < minimum or value > maximum:
        raise ValueError(f"{context} is outside {minimum}..{maximum}")
