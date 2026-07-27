"""Single declarative source for native runtime tests and suites."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


EvidenceKind = Literal[
    "self_consistency",
    "internal_invariant",
    "mac_resource_oracle",
    "retail_fixture_oracle",
    "retail_differential",
]

EVIDENCE_KINDS: tuple[EvidenceKind, ...] = (
    "self_consistency",
    "internal_invariant",
    "mac_resource_oracle",
    "retail_fixture_oracle",
    "retail_differential",
)


@dataclass(frozen=True)
class RuntimeFixtureSpec:
    filename: str
    evidence_kind: EvidenceKind
    provenance_required: bool = True


@dataclass(frozen=True)
class ExpectedFailureSpec:
    """Structured signature of a known failure, never a blanket expected-fail bit."""

    assertion_ids: tuple[str, ...] = ()
    phases: tuple[str, ...] = ()
    classifications: tuple[str, ...] = ()

    def matches(self, result: dict) -> bool:
        summary = result.get("summary", {})
        assertion_id = result.get("assertion_id") or summary.get("assertion_id")
        phase = result.get("phase") or summary.get("phase")
        classification = result.get("classification") or summary.get("classification")
        return (
            (not self.assertion_ids or assertion_id in self.assertion_ids)
            and (not self.phases or phase in self.phases)
            and (not self.classifications or classification in self.classifications)
        )


@dataclass(frozen=True)
class RuntimeTestSpec:
    name: str
    native_factory: str
    suites: tuple[str, ...]
    evidence_kind: EvidenceKind
    execution: Literal["game", "harness"] = "game"
    fixture: RuntimeFixtureSpec | None = None
    required_oracles: tuple[str, ...] = ("ui",)
    native_snapshots: tuple[str, ...] = ()
    expected_failure: ExpectedFailureSpec | None = None
    promotion_suites: tuple[str, ...] = ()
    promotion_order: int | None = None
    default_timeout: float = 300.0


TESTS = (
    RuntimeTestSpec(
        "boot_managers",
        "BootManagersTest",
        ("pr", "full"),
        "internal_invariant",
        required_oracles=(),
    ),
    RuntimeTestSpec(
        "turn_event_queue_bounds",
        "RuntimeHarnessSelfTest",
        ("pr", "full"),
        "internal_invariant",
        execution="harness",
        required_oracles=(),
    ),
    RuntimeTestSpec(
        "random_game_easy_skips_capital",
        "EasyRandomGameTest",
        ("pr", "full"),
        "self_consistency",
        required_oracles=("ui", "map"),
        native_snapshots=("ui", "map"),
    ),
    RuntimeTestSpec(
        "random_game_introductory_exits_newspaper",
        "IntroductoryRandomGameTest",
        ("pr", "full"),
        "self_consistency",
        required_oracles=("ui", "map"),
        native_snapshots=("ui", "map"),
    ),
    RuntimeTestSpec(
        "random_game_enters_map",
        "RandomGameJourneyTest",
        ("full",),
        "self_consistency",
        required_oracles=("ui", "map"),
        native_snapshots=("ui", "map"),
    ),
    RuntimeTestSpec(
        "easy_turns_advance",
        "EndTurnTest",
        ("pr", "full"),
        "internal_invariant",
        required_oracles=("ui", "map"),
        native_snapshots=("ui", "map"),
    ),
    RuntimeTestSpec(
        "city_screen_opens",
        "CityScreenTest",
        ("full",),
        "mac_resource_oracle",
        required_oracles=("ui",),
        native_snapshots=("ui",),
    ),
    RuntimeTestSpec(
        "civilian_recruitment_selection",
        "CivilianRecruitmentTest",
        ("pr", "full"),
        "internal_invariant",
        required_oracles=("map",),
        native_snapshots=("map",),
    ),
    RuntimeTestSpec(
        "diplomacy_screen_operates",
        "DiplomacyScreenTest",
        ("full",),
        "mac_resource_oracle",
        required_oracles=("ui",),
        native_snapshots=("ui",),
    ),
    RuntimeTestSpec(
        "trade_screen_operates",
        "TradeScreenTest",
        ("full",),
        "mac_resource_oracle",
        required_oracles=("ui",),
        native_snapshots=("ui",),
    ),
    RuntimeTestSpec(
        "map_zoom_toggle_remains_responsive",
        "MapZoomToggleTest",
        ("full",),
        "internal_invariant",
        required_oracles=("ui", "map"),
        native_snapshots=("ui", "map"),
    ),
    RuntimeTestSpec(
        "serialization_roundtrip",
        "SerializationRoundtripTest",
        ("pr", "full"),
        "self_consistency",
        required_oracles=(),
    ),
    RuntimeTestSpec(
        "save_load_roundtrip",
        "SaveLoadRoundtripTest",
        ("pr", "full"),
        "self_consistency",
        required_oracles=("map",),
        native_snapshots=("map",),
    ),
    RuntimeTestSpec(
        "save_stream_checkpoints",
        "SaveStreamCheckpointTest",
        ("full",),
        "self_consistency",
        required_oracles=(),
    ),
    RuntimeTestSpec(
        "load_saved_game",
        "LoadSavedGameTest",
        ("full",),
        "retail_fixture_oracle",
        fixture=RuntimeFixtureSpec(
            "beginning_of_game.imp", "retail_fixture_oracle"
        ),
        required_oracles=("map",),
        native_snapshots=("map",),
    ),
)


def find_test(name: str) -> RuntimeTestSpec | None:
    return next((test for test in TESTS if test.name == name), None)


def tests_in_suite(suite: str) -> tuple[RuntimeTestSpec, ...]:
    return tuple(test for test in TESTS if suite in test.suites)


def suite_names() -> tuple[str, ...]:
    return tuple(sorted({suite for test in TESTS for suite in test.suites}))


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
    """Fold a missing-oracle finding into a result without hiding a real failure."""
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


def apply_expected_failure(test: RuntimeTestSpec, result: dict) -> None:
    """Classify a repro result without accepting a different failure as success."""
    result["evidence_kind"] = test.evidence_kind
    expected = test.expected_failure
    if expected is None:
        return
    result["native_status"] = result.get("status")
    if result.get("status") == "passed":
        result["status"] = "failed"
        result["expectation_outcome"] = "unexpected_pass"
        result["failure"] = "XPASS: known-failure signature no longer reproduced"
        return
    if expected.matches(result):
        result["status"] = "expected_failure"
        result["expectation_outcome"] = "expected_failure"
        return
    result["expectation_outcome"] = "different_failure"
    expected_summary = {
        "assertion_ids": list(expected.assertion_ids),
        "phases": list(expected.phases),
        "classifications": list(expected.classifications),
    }
    result["expected_failure"] = expected_summary


def promotion_candidates(results: dict[str, dict]) -> tuple[RuntimeTestSpec, ...]:
    candidates = [
        test
        for test in TESTS
        if test.promotion_suites
        and results.get(test.name, {}).get("expectation_outcome") == "unexpected_pass"
    ]
    return tuple(
        sorted(
            candidates,
            key=lambda test: (
                test.promotion_order if test.promotion_order is not None else 2**31,
                test.name,
            ),
        )
    )


FIXTURES = {
    test.name: test.fixture.filename for test in TESTS if test.fixture is not None
}
