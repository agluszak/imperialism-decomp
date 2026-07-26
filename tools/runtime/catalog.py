"""Declarative catalog for instrumented runtime tests and suites."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeTestSpec:
    name: str
    suite: tuple[str, ...]
    fixture: str | None = None
    required_oracles: tuple[str, ...] = ("ui",)
    default_timeout: float = 300.0


TESTS = (
    RuntimeTestSpec("boot_managers", ("pr", "full"), required_oracles=()),
    RuntimeTestSpec("turn_event_queue_bounds", ("pr", "full"), required_oracles=()),
    RuntimeTestSpec("random_game_easy_skips_capital", ("pr", "full"), required_oracles=("ui", "map")),
    RuntimeTestSpec(
        "random_game_introductory_exits_newspaper",
        ("pr", "full"),
        required_oracles=("ui", "map"),
    ),
    RuntimeTestSpec("random_game_enters_map", ("full",), required_oracles=("ui", "map")),
    RuntimeTestSpec("easy_turns_advance", ("pr", "full"), required_oracles=("ui", "map")),
    RuntimeTestSpec("city_screen_opens", ("repro",), required_oracles=("ui",)),
    RuntimeTestSpec("transport_screen_operates", ("repro",), required_oracles=("ui",)),
    RuntimeTestSpec("civilian_recruitment_selection", ("pr", "full"), required_oracles=("map",)),
    RuntimeTestSpec("diplomacy_screen_operates", ("repro",), required_oracles=("ui",)),
    RuntimeTestSpec("trade_screen_operates", ("repro",), required_oracles=("ui",)),
    RuntimeTestSpec(
        "map_zoom_toggle_remains_responsive",
        ("repro",),
        required_oracles=("ui", "map"),
    ),
    RuntimeTestSpec("serialization_roundtrip", ("pr", "full"), required_oracles=()),
    RuntimeTestSpec("save_load_roundtrip", ("pr", "full"), required_oracles=("map",)),
    # No fixture: it saves through the document path first and replays its own bytes.
    # A committed save whose provenance cannot be checked in is worse than none --
    # the previous fixture was stale and made a correct reader look broken
    # (imperialism-decomp-cinw.17).
    # The replay consumes the live game state, so no oracle can be captured afterwards.
    RuntimeTestSpec(
        "save_stream_checkpoints",
        ("full",),
        required_oracles=(),
    ),
    RuntimeTestSpec(
        "load_saved_game",
        ("full",),
        fixture="beginning_of_game.imp",
        required_oracles=("map",),
    ),
)


def find_test(name: str) -> RuntimeTestSpec | None:
    return next((test for test in TESTS if test.name == name), None)


def tests_in_suite(suite: str) -> tuple[RuntimeTestSpec, ...]:
    return tuple(test for test in TESTS if suite in test.suite)


def suite_names() -> tuple[str, ...]:
    return tuple(sorted({suite for test in TESTS for suite in test.suite}))


def missing_required_oracles(test: RuntimeTestSpec, result: dict) -> tuple[str, ...]:
    missing = []
    for oracle in test.required_oracles:
        report = result.get(f"{oracle}_oracle")
        if not isinstance(report, dict) or report.get("status") == "skipped":
            missing.append(oracle)
    return tuple(missing)


def record_missing_oracles(
    result: dict, missing: tuple[str, ...], fallback_failure: str | None = None
) -> None:
    """Fold a missing-oracle finding into a result without hiding a real failure.

    Missing oracles are usually a *consequence* of a failure rather than a cause: the
    driver snapshots map state only on a passing finish, so a crash or a phase timeout
    guarantees the map oracle is absent.  Treating that as the failure replaced every
    such primary failure with "missing required oracle(s): map" -- the least actionable
    description available.  So the primary failure stays authoritative and the gap is
    recorded as a secondary diagnostic; only a run that otherwise passed is failed by a
    missing oracle, since there the gap really is the finding.
    """
    if not missing:
        return
    result["missing_oracles"] = list(missing)
    summary = "missing required oracle(s): " + ", ".join(missing)
    if result.get("status") == "passed":
        result["status"] = "failed"
        result["failure"] = summary
        return
    if not result.get("failure"):
        result["failure"] = fallback_failure or "runtime test failed"
    result["secondary_failures"] = [*result.get("secondary_failures", []), summary]


FIXTURES = {test.name: test.fixture for test in TESTS if test.fixture is not None}
