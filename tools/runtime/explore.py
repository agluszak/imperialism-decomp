"""Coverage-free exploratory control clicking with crash replay and minimization."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import itertools
import json
import os
from pathlib import Path
import shlex
import time
from typing import Callable, Iterator, Sequence

from tools.runtime.models import HostResult, RunConfig, RunOutcome
from tools.runtime.runner import RunRequest, RunnerDependencies, RuntimeRunner
from tools.runtime.session import execute_run


TEST_NAME = "random_control_explorer"
TRACE_NAME = "exploration-trace.jsonl"
REPLAY_NAME = "exploration-replay.txt"
REPRODUCER_NAME = "random-control-reproducer.json"
INTERESTING_CLASSIFICATIONS = {
    "crash",
    "heartbeat_stopped",
    "pump_alive_no_semantic_progress",
    "action_timeout",
}


@dataclass(frozen=True)
class ExploreAction:
    path: str
    local_x: int
    local_y: int
    tag: str | None = None
    class_name: str | None = None
    event: int | None = None


@dataclass(frozen=True)
class FailureSignature:
    classification: str
    inferior_signal: str | None
    debugger_signal: str | None
    debugger_invariant: str | None
    assertion_id: str | None
    fault_address: str | None
    fault_code: str | None
    last_control_path: str | None
    last_control_x: int | None
    last_control_y: int | None


def read_trace(path: Path) -> list[ExploreAction]:
    actions: list[ExploreAction] = []
    if not path.is_file():
        return actions
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            actions.append(
                ExploreAction(
                    path=str(entry["path"]),
                    local_x=int(entry["local_x"]),
                    local_y=int(entry["local_y"]),
                    tag=str(entry["tag"]) if entry.get("tag") is not None else None,
                    class_name=(
                        str(entry["class"]) if entry.get("class") is not None else None
                    ),
                    event=int(entry["event"]) if entry.get("event") is not None else None,
                )
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid exploration trace line {line_number}: {error}") from error
    return actions


def encode_replay(actions: Sequence[ExploreAction]) -> str:
    lines = []
    for action in actions:
        if "\t" in action.path or "\n" in action.path or "\r" in action.path:
            raise ValueError(f"control path contains an unsupported delimiter: {action.path!r}")
        lines.append(f"{action.path}\t{action.local_x}\t{action.local_y}")
    encoded = "\n".join(lines)
    if len(encoded.encode("utf-8")) >= 250_000:
        raise ValueError("replay exceeds the native 250 KB replay buffer")
    return encoded


def failure_signature(outcome: RunOutcome) -> FailureSignature | None:
    if not outcome.attempts:
        return None
    primary = outcome.attempts[0]
    classification = primary.host.classification
    if classification not in INTERESTING_CLASSIFICATIONS:
        return None
    result = outcome.result
    assertion_id = result.get("assertion_id")
    fault_address = None
    fault_code = None
    runtime = result.get("runtime")
    if isinstance(runtime, dict):
        faults = runtime.get("faults")
        if isinstance(faults, list) and faults and isinstance(faults[0], dict):
            fault = faults[0]
            if fault.get("address") is not None:
                fault_address = str(fault["address"])
            if fault.get("code") is not None:
                fault_code = str(fault["code"])

    trace = read_trace(primary.run_dir / TRACE_NAME)
    last_control = trace[-1] if trace else None
    last_control_path = last_control.path if last_control is not None else None
    if fault_address is None and primary.host.debugger_invariant is None and last_control_path is None:
        return None

    return FailureSignature(
        classification=classification,
        inferior_signal=primary.host.inferior_signal,
        debugger_signal=primary.host.debugger_signal,
        debugger_invariant=primary.host.debugger_invariant,
        assertion_id=assertion_id if isinstance(assertion_id, str) else None,
        fault_address=fault_address,
        fault_code=fault_code,
        last_control_path=last_control_path,
        last_control_x=last_control.local_x if last_control is not None else None,
        last_control_y=last_control.local_y if last_control is not None else None,
    )


def same_failure(expected: FailureSignature, outcome: RunOutcome) -> bool:
    actual = failure_signature(outcome)
    if actual is None or actual.classification != expected.classification:
        return False

    # Signals and debugger invariants are stronger than a broad host classification.
    # Compare them when the original run supplied them, but do not require fields the
    # debugger could not recover from a particular stop.
    for field_name in (
        "inferior_signal",
        "debugger_signal",
        "debugger_invariant",
        "assertion_id",
        "fault_address",
        "fault_code",
        "last_control_path",
        "last_control_x",
        "last_control_y",
    ):
        expected_value = getattr(expected, field_name)
        if expected_value is not None and getattr(actual, field_name) != expected_value:
            return False
    return True


def ddmin(
    actions: Sequence[ExploreAction],
    reproduces: Callable[[Sequence[ExploreAction]], bool],
) -> list[ExploreAction]:
    """Classic delta debugging over action subsequences."""
    current = list(actions)
    granularity = 2
    while len(current) >= 2:
        chunk_size = (len(current) + granularity - 1) // granularity
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size :]
            if not candidate:
                continue
            if reproduces(candidate):
                current = candidate
                granularity = max(granularity - 1, 2)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)
    return current


def _primary_run_dir(outcome: RunOutcome) -> Path:
    if not outcome.attempts:
        raise RuntimeError("exploration run produced no attempt")
    return outcome.attempts[0].run_dir


def _load_reproducer(
    path: Path,
) -> tuple[int, FailureSignature, list[ExploreAction]]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if parsed.get("format_version") != 1:
        raise ValueError(f"unsupported reproducer format in {path}")
    seed = int(parsed["seed"])
    signature_data = parsed["failure_signature"]
    signature = FailureSignature(
        classification=str(signature_data["classification"]),
        inferior_signal=(
            str(signature_data["inferior_signal"])
            if signature_data.get("inferior_signal") is not None
            else None
        ),
        debugger_signal=(
            str(signature_data["debugger_signal"])
            if signature_data.get("debugger_signal") is not None
            else None
        ),
        debugger_invariant=(
            str(signature_data["debugger_invariant"])
            if signature_data.get("debugger_invariant") is not None
            else None
        ),
        assertion_id=(
            str(signature_data["assertion_id"])
            if signature_data.get("assertion_id") is not None
            else None
        ),
        fault_address=(
            str(signature_data["fault_address"])
            if signature_data.get("fault_address") is not None
            else None
        ),
        fault_code=(
            str(signature_data["fault_code"])
            if signature_data.get("fault_code") is not None
            else None
        ),
        last_control_path=(
            str(signature_data["last_control_path"])
            if signature_data.get("last_control_path") is not None
            else None
        ),
        last_control_x=(
            int(signature_data["last_control_x"])
            if signature_data.get("last_control_x") is not None
            else None
        ),
        last_control_y=(
            int(signature_data["last_control_y"])
            if signature_data.get("last_control_y") is not None
            else None
        ),
    )
    actions = [
        ExploreAction(
            path=str(item["path"]),
            local_x=int(item["local_x"]),
            local_y=int(item["local_y"]),
            tag=str(item["tag"]) if item.get("tag") is not None else None,
            class_name=(
                str(item["class_name"])
                if item.get("class_name") is not None
                else None
            ),
            event=int(item["event"]) if item.get("event") is not None else None,
        )
        for item in parsed["actions"]
    ]
    return seed, signature, actions


def _write_reproducer(
    path: Path,
    seed: int,
    signature: FailureSignature,
    actions: Sequence[ExploreAction],
    source_run: Path,
) -> None:
    payload = {
        "format_version": 1,
        "test": TEST_NAME,
        "seed": seed,
        "failure_signature": asdict(signature),
        "source_run": str(source_run),
        "actions": [asdict(action) for action in actions],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ReplayStagingExecutor:
    """Stage a per-attempt replay beside result.json before launching Wine."""

    def __init__(self) -> None:
        self.replay: str | None = None

    def __call__(self, config: RunConfig) -> HostResult:
        replay_path = config.run_dir / REPLAY_NAME
        replay_path.unlink(missing_ok=True)
        if self.replay is not None:
            replay_path.write_text(self.replay, encoding="utf-8")
        return execute_run(config)


@contextmanager
def _temporary_environment(values: dict[str, str]) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run_once(
    runner: RuntimeRunner,
    executor: ReplayStagingExecutor,
    *,
    seed: int,
    steps: int,
    timeout: float,
    phase_timeout_ms: int,
    settle_ticks: int,
    replay: Sequence[ExploreAction] | None,
) -> RunOutcome:
    extra_environment = {
        "IMPERIALISM_RUNTIME_EXPLORE_MAX_ACTIONS": str(steps),
        "IMPERIALISM_RUNTIME_EXPLORE_SETTLE_TICKS": str(settle_ticks),
    }
    executor.replay = encode_replay(replay) if replay is not None else None
    try:
        with _temporary_environment(extra_environment):
            return runner.run(
                RunRequest(
                    name=TEST_NAME,
                    seed=seed,
                    timeout_seconds=timeout,
                    phase_timeout_ms=phase_timeout_ms,
                    rerun_seh=False,
                    gdb_first=True,
                    no_gdb=False,
                    require_fixtures=False,
                )
            )
    finally:
        executor.replay = None


def _runner(
    result_dir: Path, fixture_dir: Path
) -> tuple[RuntimeRunner, ReplayStagingExecutor]:
    counter = itertools.count()

    def unique_stamp() -> str:
        return f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{next(counter):04d}"

    executor = ReplayStagingExecutor()
    return (
        RuntimeRunner(
            result_dir,
            fixture_dir,
            RunnerDependencies(execute=executor, utc_stamp=unique_stamp),
        ),
        executor,
    )


def _is_benign_termination(outcome: RunOutcome) -> bool:
    if not outcome.attempts:
        return False
    host = outcome.attempts[0].host
    return (
        host.classification == "exited_without_result"
        and host.inferior_exit_code in {None, 0}
    )


def _raise_non_exploration_failure(outcome: RunOutcome) -> None:
    if outcome.result.get("status") == "passed" or _is_benign_termination(outcome):
        return
    summary = outcome.result.get("summary", {})
    failure = outcome.result.get("failure") or summary.get("primary_failure") or "unknown failure"
    classification = summary.get("classification") or outcome.result.get("classification")
    raise RuntimeError(
        f"random-control explorer failed without a crash/hang signature: "
        f"classification={classification or 'none'} failure={failure}"
    )


def run_explorer(args, *, result_dir: Path, fixture_dir: Path) -> int:
    runner, executor = _runner(result_dir, fixture_dir)

    if args.replay is not None:
        seed, expected_signature, actions = _load_reproducer(args.replay)
        outcome = _run_once(
            runner,
            executor,
            seed=seed,
            steps=len(actions),
            timeout=args.timeout,
            phase_timeout_ms=args.phase_timeout_ms,
            settle_ticks=args.settle_ticks,
            replay=actions,
        )
        signature = failure_signature(outcome)
        run_dir = _primary_run_dir(outcome)
        print(f"replay run: {run_dir}")
        if signature is None:
            _raise_non_exploration_failure(outcome)
            print("reproducer did not trigger a crash or hang")
            return 1
        if not same_failure(expected_signature, outcome):
            print(
                f"reproducer triggered a different failure: "
                f"expected={expected_signature.classification} actual={signature.classification}"
            )
            return 1
        print(f"reproduced: {signature.classification}")
        return 0

    campaign = 0
    while args.runs == 0 or campaign < args.runs:
        seed = args.seed + campaign
        outcome = _run_once(
            runner,
            executor,
            seed=seed,
            steps=args.steps,
            timeout=args.timeout,
            phase_timeout_ms=args.phase_timeout_ms,
            settle_ticks=args.settle_ticks,
            replay=None,
        )
        run_dir = _primary_run_dir(outcome)
        trace = read_trace(run_dir / TRACE_NAME)
        signature = failure_signature(outcome)
        if signature is None:
            _raise_non_exploration_failure(outcome)
            print(f"seed {seed}: no crash after {len(trace)} actions ({run_dir})")
            campaign += 1
            continue

        print(
            f"seed {seed}: {signature.classification} after {len(trace)} actions "
            f"({run_dir})"
        )
        minimized = trace
        final_run = run_dir
        if not trace:
            raise RuntimeError("random-control failure occurred before any action was recorded")
        if not args.no_minimize and len(trace) > 1:
            attempts = 0

            def reproduces(candidate: Sequence[ExploreAction]) -> bool:
                nonlocal attempts, final_run
                attempts += 1
                candidate_outcome = _run_once(
                    runner,
                    executor,
                    seed=seed,
                    steps=len(candidate),
                    timeout=args.timeout,
                    phase_timeout_ms=args.phase_timeout_ms,
                    settle_ticks=args.settle_ticks,
                    replay=candidate,
                )
                final_run = _primary_run_dir(candidate_outcome)
                matched = same_failure(signature, candidate_outcome)
                print(
                    f"minimize {attempts}: {len(candidate)} actions -> "
                    f"{'reproduced' if matched else 'no'}"
                )
                return matched

            minimized = ddmin(trace, reproduces)

        # Preserve a final bundle whose trace exactly matches the emitted reproducer,
        # including zero-reduction and one-action failures.
        final_outcome = _run_once(
            runner,
            executor,
            seed=seed,
            steps=len(minimized),
            timeout=args.timeout,
            phase_timeout_ms=args.phase_timeout_ms,
            settle_ticks=args.settle_ticks,
            replay=minimized,
        )
        final_run = _primary_run_dir(final_outcome)
        if not same_failure(signature, final_outcome):
            raise RuntimeError("random-control reproducer failed final verification")

        reproducer = final_run / REPRODUCER_NAME
        _write_reproducer(reproducer, seed, signature, minimized, run_dir)
        stable_reproducer = result_dir / REPRODUCER_NAME
        _write_reproducer(stable_reproducer, seed, signature, minimized, run_dir)
        print(f"minimal reproducer: {len(minimized)} actions")
        print(f"artifact: {reproducer}")
        print(
            "replay: just runtime-explore --replay "
            + shlex.quote(str(stable_reproducer))
        )
        return 1

    return 0
