"""Parsing and validation for the native runtime JSON result envelope."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tools.runtime.catalog import EVIDENCE_KINDS

RESULT_STATUSES = frozenset({"passed", "failed", "skipped"})
PUBLISHED_RESULT_STATUSES = RESULT_STATUSES | frozenset({"expected_failure"})
REQUIRED_RESULT_KEYS = frozenset({"name", "seed", "status", "captures_path"})
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
    allowed. Capture payloads live in the sidecar named by captures_path; Python does
    not duplicate their schemas or translate their values.
    """
    _validate_envelope(result, expected_name, expected_seed, RESULT_STATUSES, REQUIRED_RESULT_KEYS)


def validate_published_result(
    result: dict[str, Any], expected_name: str, expected_seed: int
) -> None:
    """Validate the final published result for generic runtime-capture tests.

    This is the native envelope plus catalog `evidence_kind`. Native transition
    differentials read result.json / captures.json directly and do not use this.
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


def resolve_captures_path(result: dict[str, Any], envelope_path: Path) -> Path:
    """Resolve captures_path relative to the control-channel envelope."""
    captures_path = result.get("captures_path")
    if not isinstance(captures_path, str) or not captures_path:
        raise ValueError("runtime result captures_path must be a non-empty string")
    path = Path(captures_path)
    if not path.is_absolute():
        path = envelope_path.parent / path
    return path


def load_captures(result: dict[str, Any], envelope_path: Path) -> dict[str, Any]:
    """Load the semantic capture object from the sidecar referenced by the envelope."""
    path = resolve_captures_path(result, envelope_path)
    captures = read_json_file(path)
    if captures is None:
        raise ValueError(f"runtime captures sidecar is missing or invalid: {path}")
    return captures


def attach_captures_checksum(result: dict[str, Any], envelope_path: Path) -> None:
    """Stamp sha256 of the captures sidecar onto the control envelope."""
    path = resolve_captures_path(result, envelope_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result["captures_sha256"] = digest


def write_empty_captures_sidecar(
    directory: Path, file_name: str = "captures.json"
) -> str:
    """Write an empty captures object for host-synthesized failure envelopes."""
    path = directory / file_name
    path.write_text("{}\n", encoding="utf-8")
    return file_name


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

    captures_path = result["captures_path"]
    if not isinstance(captures_path, str) or not captures_path:
        raise ValueError("runtime result captures_path must be a non-empty string")
    if "captures" in result:
        raise ValueError(
            "runtime result must not embed captures; use captures_path for the sidecar"
        )
