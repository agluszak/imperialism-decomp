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

CHECKPOINT_RANDOM_SETUP_READY = "random_setup.ready"
CHECKPOINT_COMBINED_MAP_READY = "combined_map.ready"
CHECKPOINT_CITY_ACTIVE = "city.active"
CHECKPOINT_TURN_ADVANCED = "turn.advanced"


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
}


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
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


def normalize_native_combined_map(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native driver result to the stable combined-map schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    state = _require_mapping(result.get("state"), "native state")
    map_state = _require_mapping(result.get("map_state"), "native map_state")
    root_class = state.get("root_class")
    if root_class != "TMapUberPicture":
        raise ValueError(f"native active view is {root_class!r}, expected TMapUberPicture")
    return {
        "checkpoint_id": CHECKPOINT_COMBINED_MAP_READY,
        "action_id": ACTION_COMBINED_MAP_ENTRY,
        "turn_event": _require_int(state.get("turn_event"), "native turn_event"),
        "active_view": "strategic_map",
        "nation": {
            "active": _require_int(state.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                state.get("economic_turn"), "native economic_turn"
            ),
        },
        "map": {
            "present": _require_bool(state.get("global_map"), "native global_map"),
            "wrap": _require_int(map_state.get("wrap"), "native map wrap"),
        },
        "city_orders": {
            "city_present": _require_bool(
                state.get("city_present"), "native city_present"
            ),
            "production_orders": _require_int_list(
                state.get("production_orders"), "native production_orders"
            ),
            "production_flags": _require_int_list(
                state.get("production_flags"), "native production_flags"
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
