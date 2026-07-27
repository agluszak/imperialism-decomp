"""Typed retry, postprocessing, aggregation, and publication for runtime tests."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import time
from typing import Callable

from tools.runtime.artifacts import prune_old_run_dirs
from tools.runtime.catalog import (
    FIXTURES,
    find_test,
    missing_required_oracles,
    record_missing_oracles,
)
from tools.runtime.fixtures import validate_fixture_metadata
from tools.runtime.models import (
    AttemptResult,
    HostResult,
    JsonObject,
    NativeResult,
    OracleResult,
    RunConfig,
    RunOutcome,
)
from tools.runtime.oracles.map import evaluate_map_oracle
from tools.runtime.oracles.ui import evaluate_ui_oracle
from tools.runtime.protocol import read_json_file, validate_result
from tools.runtime.session import execute_run


@dataclass(frozen=True)
class RunRequest:
    name: str
    seed: int
    timeout_seconds: float
    phase_timeout_ms: int
    rerun_seh: bool
    gdb_first: bool
    no_gdb: bool
    require_fixtures: bool


@dataclass(frozen=True)
class RunnerDependencies:
    execute: Callable[[RunConfig], HostResult] = execute_run
    ui_oracle: Callable[[JsonObject], JsonObject | None] = evaluate_ui_oracle
    map_oracle: Callable[[JsonObject, str, int], JsonObject | None] = evaluate_map_oracle
    fixture_validator: Callable[[Path, str], JsonObject] = validate_fixture_metadata
    prune: Callable[[Path, str], None] = prune_old_run_dirs
    utc_stamp: Callable[[], str] = lambda: time.strftime(
        "%Y%m%dT%H%M%SZ", time.gmtime()
    )
    process_id: Callable[[], int] = os.getpid


def record_failure(result: JsonObject, summary: str) -> None:
    if result.get("status") == "passed":
        result["status"] = "failed"
        result["failure"] = summary
        return
    if not result.get("failure"):
        result["failure"] = summary
        return
    if result.get("failure") != summary:
        result["secondary_failures"] = [
            *result.get("secondary_failures", []),
            summary,
        ]


def _validated_native(config: RunConfig, raw: JsonObject | None) -> NativeResult:
    if raw is None:
        validated: JsonObject = {
            "format_version": 1,
            "name": config.name,
            "seed": config.seed,
            "status": "failed",
            "failure": "missing result file",
        }
    else:
        validated = copy.deepcopy(raw)
        try:
            validate_result(validated, config.name, config.seed)
        except ValueError as error:
            validated = {
                "format_version": 1,
                "name": config.name,
                "seed": config.seed,
                "status": "failed",
                "failure": f"invalid native result: {error}",
                "invalid_native_result": raw,
            }
    return NativeResult(raw=raw, validated=validated)


def process_attempt(
    config: RunConfig,
    host: HostResult,
    kind: str,
    authoritative: bool,
    dependencies: RunnerDependencies,
) -> AttemptResult:
    """Validate and enrich one attempt without losing native or host evidence."""
    raw = read_json_file(config.run_dir / "result.json")
    native = _validated_native(config, raw)
    result = native.validated
    if raw is None and host.classification is not None:
        result["failure"] = host.classification

    oracle_results: list[OracleResult] = []
    evaluators = (
        ("ui", lambda: dependencies.ui_oracle(result)),
        ("map", lambda: dependencies.map_oracle(result, config.name, config.seed)),
    )
    for oracle_name, evaluator in evaluators:
        try:
            report = evaluator()
        except Exception as error:
            report = {"status": "error", "error": f"{type(error).__name__}: {error}"}
        if report is None:
            continue
        oracle_results.append(OracleResult(oracle_name, report))
        result[f"{oracle_name}_oracle"] = report
        if report.get("status") == "failed":
            record_failure(result, f"{oracle_name} oracle mismatch")
        elif report.get("status") == "error":
            record_failure(result, f"{oracle_name} oracle error: {report['error']}")

    test_spec = find_test(config.name)
    if test_spec is not None:
        record_missing_oracles(
            result,
            missing_required_oracles(test_spec, result),
            fallback_failure=host.classification,
        )
    if host.classification is not None:
        record_failure(result, host.classification)

    if raw is not None:
        (config.run_dir / "native-result.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (config.run_dir / "run.json").write_text(
        json.dumps(host.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (config.run_dir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return AttemptResult(
        kind=kind,
        authoritative=authoritative,
        run_dir=config.run_dir,
        host=host,
        native=native,
        oracles=tuple(oracle_results),
    )


def _diagnostic_summary(attempt: AttemptResult) -> JsonObject:
    return {
        "kind": attempt.kind,
        "status": attempt.status,
        "classification": attempt.host.classification,
        "artifact_path": str(attempt.run_dir),
        "run_dir": str(attempt.run_dir),
    }


def _result_summary(result: JsonObject, attempts: list[AttemptResult]) -> JsonObject:
    primary = attempts[0]
    return {
        "duration_seconds": primary.host.duration_seconds,
        "phase": result.get("phase") or primary.host.phase,
        "classification": primary.host.classification,
        "action": result.get("last_action") or primary.host.action,
        "artifact_path": str(primary.run_dir),
        "primary_failure": result.get("failure"),
        "assertion_id": result.get("assertion_id"),
        "diagnostic_outcomes": [
            _diagnostic_summary(attempt) for attempt in attempts[1:]
        ],
    }


def format_console_summary(result: JsonObject) -> str:
    summary = result.get("summary", {})
    diagnostics = summary.get("diagnostic_outcomes", [])
    diagnostic_text = ",".join(
        f"{item.get('kind')}={item.get('status')}/{item.get('classification') or 'none'}"
        for item in diagnostics
    ) or "none"
    return (
        f"runtime {result.get('name')}: {result.get('status')} "
        f"duration={summary.get('duration_seconds')}s "
        f"phase={summary.get('phase') or 'unknown'} "
        f"classification={summary.get('classification') or 'none'} "
        f"action={summary.get('action') or 'none'} "
        f"assertion={summary.get('assertion_id') or 'none'} "
        f"artifacts={summary.get('artifact_path') or 'none'} "
        f"failure={summary.get('primary_failure') or 'none'} diagnostics={diagnostic_text}"
    )


class RuntimeRunner:
    def __init__(
        self,
        result_dir: Path,
        fixture_dir: Path,
        dependencies: RunnerDependencies | None = None,
    ) -> None:
        self.result_dir = result_dir
        self.fixture_dir = fixture_dir
        self.dependencies = dependencies or RunnerDependencies()

    def _publish_without_attempt(self, result: JsonObject, exit_code: int) -> RunOutcome:
        result["summary"] = {
            "duration_seconds": None,
            "phase": None,
            "classification": None,
            "action": None,
            "artifact_path": str(self.result_dir / f"{result['name']}.json"),
            "primary_failure": result.get("failure"),
            "assertion_id": result.get("assertion_id"),
            "diagnostic_outcomes": [],
        }
        serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
        (self.result_dir / f"{result['name']}.json").write_text(
            serialized, encoding="utf-8"
        )
        return RunOutcome(result=result, exit_code=exit_code)

    def _fixture(self, request: RunRequest) -> tuple[Path | None, JsonObject | None, RunOutcome | None]:
        fixture_name = FIXTURES.get(request.name)
        if fixture_name is None:
            return None, None, None
        fixture = self.fixture_dir / fixture_name
        if not fixture.is_file():
            result: JsonObject = {
                "format_version": 1,
                "name": request.name,
                "status": "failed" if request.require_fixtures else "skipped",
                "failure": (
                    f"missing local save fixture {fixture}; place a retail-derived "
                    "save there to enable this test"
                ),
            }
            return fixture, None, self._publish_without_attempt(
                result, 1 if request.require_fixtures else 0
            )
        try:
            metadata = self.dependencies.fixture_validator(fixture, request.name)
        except ValueError as error:
            result = {
                "format_version": 1,
                "name": request.name,
                "status": "failed",
                "failure": str(error),
            }
            return fixture, None, self._publish_without_attempt(result, 1)
        return fixture, metadata, None

    def _attempt(
        self,
        request: RunRequest,
        run_dir: Path,
        fixture: Path | None,
        fixture_metadata: JsonObject | None,
        *,
        use_gdb: bool,
        kind: str,
        authoritative: bool,
        winedebug: str | None = None,
        wine_log_name: str = "wine.log",
        run_id: str | None = None,
    ) -> AttemptResult:
        run_dir.mkdir(parents=True, exist_ok=True)
        config = RunConfig(
            name=request.name,
            run_dir=run_dir,
            seed=request.seed,
            timeout_seconds=request.timeout_seconds,
            phase_timeout_ms=request.phase_timeout_ms,
            use_gdb=use_gdb,
            winedebug=winedebug,
            wine_log_name=wine_log_name,
            fixture=fixture,
            fixture_metadata=fixture_metadata,
        )
        host = self.dependencies.execute(config).with_invocation(config, run_id)
        return process_attempt(
            config, host, kind, authoritative, self.dependencies
        )

    def run(self, request: RunRequest) -> RunOutcome:
        self.result_dir.mkdir(parents=True, exist_ok=True)
        fixture, fixture_metadata, early = self._fixture(request)
        if early is not None:
            return early

        run_id = (
            f"{request.name}-{self.dependencies.utc_stamp()}-"
            f"{self.dependencies.process_id()}"
        )
        run_dir = self.result_dir / run_id
        debugger_first = request.gdb_first and not request.no_gdb
        primary = self._attempt(
            request,
            run_dir,
            fixture,
            fixture_metadata,
            use_gdb=debugger_first,
            kind="primary_gdb" if debugger_first else "primary_wine",
            authoritative=True,
            run_id=run_id,
        )
        attempts = [primary]
        result = copy.deepcopy(primary.native.validated)
        failed = primary.status != "passed" or primary.host.classification is not None

        if failed and not debugger_first and not request.no_gdb:
            diagnostic = self._attempt(
                request,
                run_dir / "gdb-rerun",
                fixture,
                fixture_metadata,
                use_gdb=True,
                kind="diagnostic_gdb",
                authoritative=False,
            )
            attempts.append(diagnostic)
            if diagnostic.status == "passed" and diagnostic.host.classification is None:
                result["classification"] = "debugger_sensitive_non_reproduction"
            result["diagnostic_gdb"] = _diagnostic_summary(diagnostic)

        if failed and request.rerun_seh:
            diagnostic = self._attempt(
                request,
                run_dir / "seh-rerun",
                fixture,
                fixture_metadata,
                use_gdb=not request.no_gdb,
                kind="diagnostic_seh",
                authoritative=False,
                winedebug="+seh",
                wine_log_name="wine-seh.log",
            )
            attempts.append(diagnostic)
            result["diagnostic_seh"] = _diagnostic_summary(diagnostic)

        result["host"] = primary.host.to_json()
        result["attempts"] = [attempt.to_json() for attempt in attempts]
        result["summary"] = _result_summary(result, attempts)
        serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
        (run_dir / "result.json").write_text(serialized, encoding="utf-8")
        (self.result_dir / f"{request.name}.json").write_text(
            serialized, encoding="utf-8"
        )
        self.dependencies.prune(self.result_dir, request.name)

        exit_code = 0
        if primary.host.classification is not None:
            exit_code = 1
        elif primary.host.inferior_exit_code not in {None, 0}:
            exit_code = 1
        elif result.get("status") != "passed":
            exit_code = 1
        return RunOutcome(result=result, attempts=tuple(attempts), exit_code=exit_code)
