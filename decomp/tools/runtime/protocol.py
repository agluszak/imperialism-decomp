"""Parsing and validation for the native runtime JSON result envelope."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FORMAT_VERSION = 2
RESULT_STATUSES = frozenset({"passed", "failed", "skipped"})
RESULT_ENVELOPE_KEYS = frozenset(
    {"format_version", "name", "seed", "status", "captures"}
)


def read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def validate_result(result: dict[str, Any], expected_name: str, expected_seed: int) -> None:
    """Validate only the version-2 runtime-result envelope.

    Capture payloads are owned by their semantic consumers.  Python deliberately does
    not duplicate their schemas or translate their values.
    """
    unexpected = set(result) - RESULT_ENVELOPE_KEYS
    if unexpected:
        raise ValueError(
            "unexpected runtime result field(s): " + ", ".join(sorted(unexpected))
        )
    missing = RESULT_ENVELOPE_KEYS - set(result)
    if missing:
        raise ValueError(
            "missing runtime result field(s): " + ", ".join(sorted(missing))
        )
    if (
        isinstance(result["format_version"], bool)
        or not isinstance(result["format_version"], int)
        or result["format_version"] != FORMAT_VERSION
    ):
        raise ValueError(
            f"unsupported runtime result format_version {result.get('format_version')!r}"
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
