"""Pure host-side runtime process classification."""

from __future__ import annotations


HEARTBEAT_STALE_SECONDS = 15.0
FIRST_HEARTBEAT_SECONDS = 60.0


def classify_poll(
    heartbeat: dict | None,
    heartbeat_age_seconds: float | None,
    no_progress_budget_seconds: float,
    stale_budget_seconds: float = HEARTBEAT_STALE_SECONDS,
    process_age_seconds: float | None = None,
    first_heartbeat_budget_seconds: float = FIRST_HEARTBEAT_SECONDS,
) -> str | None:
    if heartbeat is None or heartbeat_age_seconds is None:
        if process_age_seconds is not None and process_age_seconds > first_heartbeat_budget_seconds:
            return "heartbeat_stopped"
        return None
    if heartbeat_age_seconds > stale_budget_seconds:
        return "heartbeat_stopped"
    if heartbeat.get("hold"):
        return None
    elapsed_ms = heartbeat.get("elapsed_ms")
    last_progress_ms = heartbeat.get("last_progress_ms")
    if (
        isinstance(elapsed_ms, int)
        and isinstance(last_progress_ms, int)
        and elapsed_ms - last_progress_ms > no_progress_budget_seconds * 1000.0
    ):
        return "pump_alive_no_semantic_progress"
    return None


def classify_exit(returncode: int, result_exists: bool) -> str | None:
    if result_exists:
        return None
    return "crash" if returncode != 0 else "exited_without_result"


def no_progress_budget_seconds(phase_timeout_ms: int) -> float:
    return phase_timeout_ms / 1000.0 * 1.5 + HEARTBEAT_STALE_SECONDS
