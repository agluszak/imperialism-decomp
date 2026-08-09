"""Parsing and validation for the native runtime JSON result envelope."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.runtime.catalog import EVIDENCE_KINDS

RESULT_STATUSES = frozenset({"passed", "failed", "skipped"})
PUBLISHED_RESULT_STATUSES = RESULT_STATUSES | frozenset({"expected_failure"})
REQUIRED_RESULT_KEYS = frozenset({"name", "seed", "status", "captures"})
REQUIRED_PUBLISHED_RESULT_KEYS = REQUIRED_RESULT_KEYS | frozenset({"evidence_kind"})


def read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def validate_result(result: dict[str, Any], expected_name: str, expected_seed: int) -> None:
    """Validate the native runtime-result envelope.

    Required keys must be present with the expected types. Extra top-level fields are
    allowed. Capture payloads are owned by their semantic consumers; Python deliberately
    does not duplicate their schemas or translate their values.
    """
    _validate_envelope(result, expected_name, expected_seed, RESULT_STATUSES, REQUIRED_RESULT_KEYS)


def validate_published_result(
    result: dict[str, Any], expected_name: str, expected_seed: int
) -> None:
    """Validate the final published result consumed by Rust differentials.

    This is the native envelope plus catalog `evidence_kind`. Pre-enrichment
    `native-result.json` files are deliberately not accepted here.
    """
    _validate_envelope(
        result,
        expected_name,
        expected_seed,
        PUBLISHED_RESULT_STATUSES,
        REQUIRED_PUBLISHED_RESULT_KEYS,
    )
    evidence_kind = result["evidence_kind"]
    if not isinstance(evidence_kind, str) or evidence_kind not in EVIDENCE_KINDS:
        raise ValueError(f"invalid runtime result evidence_kind {evidence_kind!r}")


def _validate_envelope(
    result: dict[str, Any],
    expected_name: str,
    expected_seed: int,
    allowed_statuses: frozenset[str],
    required_keys: frozenset[str],
) -> None:
    missing = required_keys - set(result)
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
    if not isinstance(result["status"], str) or result["status"] not in allowed_statuses:
        raise ValueError(f"invalid runtime result status {result.get('status')!r}")

    if not isinstance(result["captures"], dict):
        raise ValueError("runtime result captures must be an object")
