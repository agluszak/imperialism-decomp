"""Typed host-side models for semantic runtime attempts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


JsonObject = dict[str, Any]


@dataclass(frozen=True)
class RunConfig:
    name: str
    run_dir: Path
    seed: int
    timeout_seconds: float
    use_gdb: bool
    winedebug: str | None = None
    wine_log_name: str = "wine.log"
    fixture: Path | None = None
    fixture_metadata: JsonObject | None = None


@dataclass(frozen=True)
class HostResult:
    classification: str | None
    display: str
    artifact_dir: Path
    duration_seconds: float
    phase_seconds: dict[str, float]
    phase: str | None
    action: str | None
    wine_exit: int | None
    proxy_pid: int | None
    proxy_exit_code: int | None
    gdb_pid: int | None
    gdb_exit_code: int | None
    inferior_pid: int | None
    inferior_exit_code: int | None
    inferior_terminal_reason: str | None
    inferior_signal: str | None
    debugger: str
    debugger_stop_count: int
    debugger_transport_error: str | None
    debugger_invariant: str | None
    debugger_signal: str | None
    game_dir: Path
    provenance: JsonObject
    fixture_metadata: JsonObject | None = None
    run_id: str | None = None
    seed: int | None = None
    timeout_seconds: float | None = None
    # What the scenario was waiting for when the run ended, from the heartbeat's `await`
    # object. A stall used to report only phase and action, which says that nothing
    # happened but not what the scenario expected to happen.
    awaiting: str | None = None
    awaiting_source: str | None = None
    awaiting_observations: str | None = None

    def to_json(self) -> JsonObject:
        result: JsonObject = {
            "classification": self.classification,
            "display": self.display,
            "artifact_dir": str(self.artifact_dir),
            "run_dir": str(self.artifact_dir),
            "duration_seconds": self.duration_seconds,
            "phase_seconds": dict(self.phase_seconds),
            "phase": self.phase,
            "action": self.action,
            "awaiting": self.awaiting,
            "awaiting_source": self.awaiting_source,
            "awaiting_observations": self.awaiting_observations,
            "wine_exit": self.wine_exit,
            "proxy_pid": self.proxy_pid,
            "proxy_exit_code": self.proxy_exit_code,
            "gdb_pid": self.gdb_pid,
            "gdb_exit_code": self.gdb_exit_code,
            "inferior_pid": self.inferior_pid,
            "inferior_exit_code": self.inferior_exit_code,
            "inferior_terminal_reason": self.inferior_terminal_reason,
            "inferior_signal": self.inferior_signal,
            "debugger": self.debugger,
            "debugger_stop_count": self.debugger_stop_count,
            "debugger_transport_error": self.debugger_transport_error,
            "debugger_invariant": self.debugger_invariant,
            "debugger_signal": self.debugger_signal,
            "game_dir": str(self.game_dir),
            "provenance": self.provenance,
        }
        optional = {
            "fixture_metadata": self.fixture_metadata,
            "run_id": self.run_id,
            "seed": self.seed,
            "timeout_seconds": self.timeout_seconds,
        }
        result.update({key: value for key, value in optional.items() if value is not None})
        return result

    def with_invocation(self, config: RunConfig, run_id: str | None) -> "HostResult":
        return HostResult(
            **{
                **self.__dict__,
                "fixture_metadata": config.fixture_metadata,
                "run_id": run_id,
                "seed": config.seed,
                "timeout_seconds": config.timeout_seconds,
            }
        )


@dataclass(frozen=True)
class OracleResult:
    name: str
    report: JsonObject


@dataclass(frozen=True)
class NativeResult:
    raw: JsonObject | None
    validated: JsonObject


@dataclass(frozen=True)
class AttemptResult:
    kind: str
    authoritative: bool
    run_dir: Path
    host: HostResult
    native: NativeResult
    oracles: tuple[OracleResult, ...]

    @property
    def status(self) -> str | None:
        value = self.native.validated.get("status")
        return value if isinstance(value, str) else None

    def to_json(self) -> JsonObject:
        return {
            "kind": self.kind,
            "authoritative": self.authoritative,
            "run_dir": str(self.run_dir),
            "status": self.status,
            "classification": self.host.classification,
            "host": self.host.to_json(),
            "native": self.native.raw,
            "oracles": {oracle.name: oracle.report for oracle in self.oracles},
        }


@dataclass(frozen=True)
class RunOutcome:
    result: JsonObject
    attempts: tuple[AttemptResult, ...] = field(default_factory=tuple)
    exit_code: int = 1
