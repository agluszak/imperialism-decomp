"""Normalization and leakage classification for repeated runtime suites."""

from __future__ import annotations

import copy


VOLATILE_KEYS = {
    "artifact_dir",
    "artifact_path",
    "attempts",
    "duration_seconds",
    "elapsed_ms",
    "game_dir",
    "host",
    "idle_ticks",
    "phase_seconds",
    "provenance",
    "run_dir",
    "run_id",
    "summary",
    "t_ms",
}


def _without_volatile(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _without_volatile(child)
            for key, child in sorted(value.items())
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_without_volatile(child) for child in value]
    return copy.deepcopy(value)


def normalized_observation(result: dict) -> dict:
    """Retain semantic output while deleting timing, PID, and artifact noise."""
    return _without_volatile(result)  # type: ignore[return-value]


def _section(result: dict, keys: tuple[str, ...]) -> dict:
    return {key: result.get(key) for key in keys if key in result}


def classify_leaks(
    baseline: dict[str, dict], candidate: dict[str, dict], comparison_kind: str
) -> list[dict]:
    findings: list[dict] = []
    if set(baseline) != set(candidate):
        findings.append(
            {
                "kind": "registry_leakage",
                "comparison": comparison_kind,
                "baseline": sorted(baseline),
                "candidate": sorted(candidate),
            }
        )
        return findings
    for name in sorted(baseline):
        left = baseline[name]
        right = candidate[name]
        if left.get("name") != name or right.get("name") != name:
            findings.append(
                {"kind": "registry_leakage", "comparison": comparison_kind, "test": name}
            )
        if left.get("seed") != right.get("seed"):
            findings.append(
                {"kind": "rng_leakage", "comparison": comparison_kind, "test": name}
            )
        save_keys = ("serialization_roundtrip", "save_checkpoints", "map_state")
        if _section(left, save_keys) != _section(right, save_keys):
            findings.append(
                {"kind": "save_leakage", "comparison": comparison_kind, "test": name}
            )
        if normalized_observation(left) != normalized_observation(right):
            kind = (
                "debugger_leakage"
                if comparison_kind == "gdb"
                else "order_leakage"
                if comparison_kind == "reverse_order"
                else "observation_leakage"
            )
            findings.append({"kind": kind, "comparison": comparison_kind, "test": name})
    return findings
