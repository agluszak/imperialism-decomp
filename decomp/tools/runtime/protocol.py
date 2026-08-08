"""Parsing and validation for the native runtime JSON result envelope."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RESULT_STATUSES = frozenset({"passed", "failed", "skipped"})
REQUIRED_RESULT_KEYS = frozenset({"name", "seed", "status", "captures"})


def read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def validate_result(result: dict[str, Any], expected_name: str, expected_seed: int) -> None:
    """Validate the runtime-result envelope.

    Required keys must be present with the expected types. Extra top-level fields are
    allowed. Capture payloads are owned by their semantic consumers; Python deliberately
    does not duplicate their schemas or translate their values.
    """
    missing = REQUIRED_RESULT_KEYS - set(result)
    if missing:
        raise ValueError(
            "missing runtime result field(s): " + ", ".join(sorted(missing))
        )
    if result["name"] != expected_name:
        raise ValueError(f"driver ran {result.get('name')!r}, requested {expected_name!r}")
    if (
        isinstance(result["seed"], bool)
        or not isinstance(result["seed"], int)
        or result["seed"] != expected_seed
    ):
        raise ValueError(f"driver ran with seed {result.get('seed')}, requested {expected_seed}")
    if not isinstance(result["status"], str) or result["status"] not in RESULT_STATUSES:
        raise ValueError(f"invalid runtime result status {result.get('status')!r}")

    if not isinstance(result["captures"], dict):
        raise ValueError("runtime result captures must be an object")
