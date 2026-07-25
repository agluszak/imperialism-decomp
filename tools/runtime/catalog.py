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
    RuntimeTestSpec("random_game_enters_map", ("full",), required_oracles=("ui", "map")),
    RuntimeTestSpec("easy_turns_advance", ("repro",), required_oracles=("ui", "map")),
    RuntimeTestSpec("city_screen_opens", ("repro",), required_oracles=("ui",)),
    RuntimeTestSpec("trade_screen_operates", ("repro",), required_oracles=("ui",)),
    RuntimeTestSpec(
        "map_zoom_toggle_remains_responsive",
        ("repro",),
        required_oracles=("ui", "map"),
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


FIXTURES = {test.name: test.fixture for test in TESTS if test.fixture is not None}
