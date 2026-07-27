"""Validation for local retail save fixtures and their provenance sidecars."""

from __future__ import annotations

import json
from pathlib import Path

from tools.runtime.wine import file_identity


FIXTURE_METADATA_SCHEMA = 1


def fixture_sidecar_path(fixture: Path) -> Path:
    return fixture.with_suffix(fixture.suffix + ".json")


def validate_fixture_metadata(fixture: Path, scenario: str) -> dict[str, object]:
    sidecar = fixture_sidecar_path(fixture)
    try:
        metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"missing or invalid fixture sidecar {sidecar}: {error}") from error
    if not isinstance(metadata, dict):
        raise ValueError(f"fixture sidecar {sidecar} must contain a JSON object")
    identity = file_identity(fixture)
    requirements = {
        "schema": FIXTURE_METADATA_SCHEMA,
        "file": fixture.name,
        "sha256": identity["sha256"],
        "size": identity["size"],
        "scenario": scenario,
    }
    for field, expected in requirements.items():
        if metadata.get(field) != expected:
            raise ValueError(
                f"fixture sidecar {sidecar} has {field}={metadata.get(field)!r}; "
                f"expected {expected!r}"
            )
    if not isinstance(metadata.get("format_version"), int):
        raise ValueError(f"fixture sidecar {sidecar} requires integer format_version")
    instructions = metadata.get("creation_instructions")
    if not isinstance(instructions, str) or not instructions.strip():
        raise ValueError(f"fixture sidecar {sidecar} requires creation_instructions")
    return metadata
