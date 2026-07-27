"""Versioned parsing and validation for the native runtime JSON protocol."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.runtime.catalog import EVIDENCE_KINDS


FORMAT_VERSION = 1


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
