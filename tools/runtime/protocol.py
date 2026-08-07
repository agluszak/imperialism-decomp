"""Versioned parsing and validation for the native runtime JSON protocol."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.runtime.catalog import EVIDENCE_KINDS


FORMAT_VERSION = 1
GAME_SNAPSHOT_SCHEMA = "imperialism.game_snapshot.v1"
GAME_SNAPSHOT_SECTIONS = ("metadata", "rng", "world")
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
    for name in ("metadata", "rng", "world"):
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
