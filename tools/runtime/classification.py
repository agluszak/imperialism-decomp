"""Pure host-side runtime process classification."""

from __future__ import annotations


HEARTBEAT_STALE_SECONDS = 5.0
FIRST_HEARTBEAT_SECONDS = 60.0


def classify_poll(
    heartbeat: dict | None,
    heartbeat_age_seconds: float | None,
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
    return None


def classify_exit(
    returncode: int, result_exists: bool, saw_heartbeat: bool = True
) -> str | None:
    """Classify a runtime process that has exited without being killed by us.

    `saw_heartbeat` separates two failures that a non-zero exit code alone conflates:
    the game running and then dying, versus the game never getting far enough to run.
    Wine, X or the wineserver failing to come up under machine load also exits non-zero
    with no result file, and reporting that as `crash` sends whoever reads the run
    hunting for a bug in the port that is not there.

    A process that never wrote a heartbeat never reached the scenario, so it is reported
    as `exited_before_first_heartbeat`. That is deliberately not called a harness fault:
    an early crash in startup code looks the same from here, and the run bundle's
    wine.log is what tells the two apart. The classification only says which half of the
    search space to look in. Defaults to True so callers that cannot observe liveness
    keep the previous behaviour.
    """
    if result_exists:
        return None
    if returncode == 0:
        return "exited_without_result"
    return "crash" if saw_heartbeat else "exited_before_first_heartbeat"


def classify_inferior_exit(
    terminal_reason: str,
    exit_code: int | None,
    signal_name: str | None,
    result_exists: bool,
) -> str | None:
    if terminal_reason == "exited-signalled" or signal_name is not None:
        return "crash"
    if result_exists:
        return None
    if exit_code not in {None, 0}:
        return "crash"
    return "exited_without_result"
