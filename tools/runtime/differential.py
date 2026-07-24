"""Run one semantic trace tape against the original and matching recomp."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import time

import yaml

from tools.runtime.debug.address_map import matching_addresses
from tools.runtime.debug.binary import direct_call_target_after
from tools.runtime.debug.mi_process import DebuggerTransportError
from tools.runtime.debug.session import GdbSession, is_terminal_stop
from tools.runtime.wine import (
    initialize_wine_prefix,
    prefix_environment,
    retail_game_dir,
    shut_down_wine_prefix,
    windows_path,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
SCENARIO_DIR = REPO_ROOT / "tests/runtime/scenarios"
FIXTURE_DIR = REPO_ROOT / "tests/runtime/fixtures"
RESULT_DIR = BUILD_DIR / "differential-results"


@dataclass(frozen=True)
class Probe:
    probe_id: str
    original_address: int
    fields: dict[str, str]


@dataclass(frozen=True)
class Scenario:
    name: str
    fixture: Path
    probes: tuple[Probe, ...]
    stop_probe: str
    stop_field: str
    stop_value: int
    timeout_seconds: float
    initialization_owner_address: int
    before_shell_callee_address: int
    replay_probe: str
    replay_field: str
    replay_value: int


def load_scenario(name: str) -> Scenario:
    path = SCENARIO_DIR / f"{name}.yml"
    if not path.is_file():
        raise SystemExit(f"unknown differential scenario {name!r}: missing {path}")
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or parsed.get("format_version") != 1:
        raise SystemExit(f"unsupported differential scenario format in {path}")
    fixture_name = parsed.get("start", {}).get("fixture")
    fixture_root = Path(os.environ.get("IMPERIALISM_SAVE_FIXTURES", FIXTURE_DIR))
    fixture = fixture_root / fixture_name
    if not fixture.is_file():
        raise SystemExit(f"missing differential fixture {fixture}")
    probes = tuple(
        Probe(
            probe_id=entry["id"],
            original_address=int(entry["original_address"], 0)
            if isinstance(entry["original_address"], str)
            else int(entry["original_address"]),
            fields=dict(entry.get("capture", {})),
        )
        for entry in parsed.get("probes", [])
    )
    stop = parsed.get("stop", {})
    deferred = parsed.get("start", {}).get("defer_shell_command_until", {})
    replay = deferred.get("after_probe", {})
    return Scenario(
        name=str(parsed.get("name", name)),
        fixture=fixture,
        probes=probes,
        stop_probe=str(stop["probe"]),
        stop_field=str(stop["field"]),
        stop_value=int(stop["equals"], 0)
        if isinstance(stop["equals"], str)
        else int(stop["equals"]),
        timeout_seconds=float(parsed.get("timeout_seconds", 90)),
        initialization_owner_address=int(deferred["owner_address"], 0),
        before_shell_callee_address=int(deferred["after_call_to"], 0),
        replay_probe=str(replay["probe"]),
        replay_field=str(replay["field"]),
        replay_value=int(replay["equals"], 0)
        if isinstance(replay["equals"], str)
        else int(replay["equals"]),
    )


def first_divergence(original: list[dict], recomp: list[dict]) -> dict | None:
    count = max(len(original), len(recomp))
    for index in range(count):
        left = original[index] if index < len(original) else None
        right = recomp[index] if index < len(recomp) else None
        if left != right:
            return {"index": index, "original": left, "recomp": right}
    return None


def _write_trace(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _capture_fields(session: GdbSession, probe: Probe) -> dict[str, int | str]:
    fields: dict[str, int | str] = {}
    for name, expression in probe.fields.items():
        value = session.evaluate(expression)
        try:
            fields[name] = int(value, 0)
        except ValueError:
            fields[name] = value
    return fields


def run_binary(
    scenario: Scenario,
    kind: str,
    executable: Path,
    addresses: dict[str, int],
    control_addresses: dict[str, int],
    run_dir: Path,
    timeout_seconds: float,
) -> list[dict]:
    artifact_dir = run_dir / kind
    artifact_dir.mkdir(parents=True, exist_ok=True)
    prefix = artifact_dir / "prefix"
    environment = prefix_environment(prefix)
    initialize_wine_prefix(prefix, environment)
    staged_fixture = prefix / "drive_c" / "imperialism-diff.imp"
    shutil.copy2(scenario.fixture, staged_fixture)
    fixture_argument = windows_path(staged_fixture, environment)
    session = GdbSession(
        executable,
        retail_game_dir(),
        environment,
        artifact_dir,
        arguments=(fixture_argument,),
    )
    records: list[dict] = []
    occurrences: dict[str, int] = {}
    shell_command_address = direct_call_target_after(
        executable,
        control_addresses["initialization_owner"],
        control_addresses["before_shell_callee"],
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        session.start(auto_continue=False)
        breakpoint_roles: dict[str, tuple[str, Probe | None]] = {}
        deferred_number = session.set_breakpoint(shell_command_address)
        breakpoint_roles[deferred_number] = ("defer_shell_command", None)
        replay_number: str | None = None
        replay_address: int | None = None
        for probe in scenario.probes:
            number = session.set_breakpoint(addresses[probe.probe_id])
            breakpoint_roles[number] = ("probe", probe)
        deferred_context: tuple[int, int, int, int] | None = None
        session.continue_inferior()
        while time.monotonic() < deadline:
            stop = session.wait_for_stop(min(1.0, deadline - time.monotonic()))
            if stop is None:
                if session.process.poll() is not None:
                    raise RuntimeError(
                        f"{kind} exited with {session.process.returncode} before the stop checkpoint"
                    )
                continue
            if is_terminal_stop(stop):
                raise RuntimeError(f"{kind} exited before the stop checkpoint")
            if stop.reason != "breakpoint-hit":
                session.capture_stop(f"unexpected-{stop.signal_name or stop.reason}", stop)
                raise RuntimeError(
                    f"{kind} stopped unexpectedly: {stop.signal_name or stop.reason}"
                )
            role = breakpoint_roles.get(stop.breakpoint_number or "")
            if role is None:
                raise RuntimeError(
                    f"{kind} hit unknown breakpoint {stop.breakpoint_number}"
                )
            role_name, probe = role
            if role_name == "defer_shell_command":
                if deferred_context is not None:
                    raise RuntimeError(f"{kind} entered the deferred shell command twice")
                app = int(session.evaluate("$ecx"), 0)
                command_info = int(session.evaluate("*(unsigned int*)($esp+4)"), 0)
                shell_command = int(
                    session.evaluate(f"*(int*)0x{command_info + 0x10:08x}"), 0
                )
                if shell_command != 1:
                    raise RuntimeError(
                        f"{kind} expected CCommandLineInfo::FileOpen (1), got {shell_command}"
                    )
                filename = int(
                    session.evaluate(f"*(unsigned int*)0x{command_info + 0x14:08x}"), 0
                )
                deferred_context = (app, command_info, shell_command, filename)
                session.assign(f"*(int*)0x{command_info + 0x10:08x}", 0)
                session.continue_inferior()
                continue
            if role_name == "replay_shell_command":
                if deferred_context is None:
                    raise RuntimeError(f"{kind} reached replay before shell-command deferral")
                if replay_number is None or replay_address is None:
                    raise RuntimeError(f"{kind} reached an unconfigured shell-command replay")
                app, command_info, shell_command, filename = deferred_context
                session.delete_breakpoint(deferred_number)
                session.delete_breakpoint(replay_number)
                session.assign(
                    f"*(int*)0x{command_info + 0x10:08x}", shell_command
                )
                vtable = int(session.evaluate(f"*(unsigned int*)0x{app:08x}"), 0)
                open_document = int(
                    session.evaluate(f"*(unsigned int*)0x{vtable + 0x84:08x}"), 0
                )
                stack = int(session.evaluate("$esp"), 0)
                session.assign(f"*(unsigned int*)0x{stack - 4:08x}", filename)
                session.assign(f"*(unsigned int*)0x{stack - 8:08x}", replay_address)
                session.assign("$esp", stack - 8)
                session.assign("$ecx", app)
                session.assign("$eip", open_document)
                session.continue_inferior()
                continue
            if probe is None:
                raise RuntimeError(f"{kind} probe breakpoint has no probe definition")
            occurrence = occurrences.get(probe.probe_id, 0) + 1
            occurrences[probe.probe_id] = occurrence
            fields = _capture_fields(session, probe)
            record = {
                "seq": len(records),
                "probe": probe.probe_id,
                "occurrence": occurrence,
                "fields": fields,
            }
            records.append(record)
            if (
                deferred_context is not None
                and replay_number is None
                and probe.probe_id == scenario.replay_probe
                and fields.get(scenario.replay_field) == scenario.replay_value
            ):
                replay_address = int(
                    session.evaluate("*(unsigned int*)$esp"), 0
                )
                replay_number = session.set_breakpoint(replay_address)
                breakpoint_roles[replay_number] = ("replay_shell_command", None)
            if (
                probe.probe_id == scenario.stop_probe
                and fields.get(scenario.stop_field) == scenario.stop_value
            ):
                break
            session.continue_inferior()
        else:
            session.interrupt_and_capture("differential-timeout")
            raise RuntimeError(f"{kind} timed out before the stop checkpoint")
    finally:
        session.close()
        shut_down_wine_prefix(environment)
        shutil.rmtree(prefix, ignore_errors=True)
    _write_trace(artifact_dir / "trace.ndjson", records)
    return records


def run_scenario(scenario: Scenario, timeout: float | None = None) -> int:
    timeout_seconds = scenario.timeout_seconds if timeout is None else timeout
    original_executable = Path(os.environ.get("ORIGINAL_BINARY", "")).resolve()
    if not original_executable.is_file():
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    recomp_executable = BUILD_DIR / "Imperialism.exe"
    original_addresses = tuple(probe.original_address for probe in scenario.probes)
    control_original = {
        "initialization_owner": scenario.initialization_owner_address,
        "before_shell_callee": scenario.before_shell_callee_address,
    }
    all_original_addresses = original_addresses + tuple(control_original.values())
    recomp_map = matching_addresses("IMPERIALISM", BUILD_DIR, all_original_addresses)
    run_id = f"{scenario.name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = RESULT_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    original = run_binary(
        scenario,
        "original",
        original_executable,
        {probe.probe_id: probe.original_address for probe in scenario.probes},
        control_original,
        run_dir,
        timeout_seconds,
    )
    recomp = run_binary(
        scenario,
        "recomp",
        recomp_executable,
        {probe.probe_id: recomp_map[probe.original_address] for probe in scenario.probes},
        {name: recomp_map[address] for name, address in control_original.items()},
        run_dir,
        timeout_seconds,
    )
    divergence = first_divergence(original, recomp)
    result = {
        "format_version": 1,
        "scenario": scenario.name,
        "status": "matched" if divergence is None else "diverged",
        "original_records": len(original),
        "recomp_records": len(recomp),
        "first_divergence": divergence,
        "run_dir": str(run_dir),
    }
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (run_dir / "result.json").write_text(serialized, encoding="utf-8")
    (RESULT_DIR / f"{scenario.name}.json").write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if divergence is None else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("--timeout", type=float)
    args = parser.parse_args()
    try:
        return run_scenario(load_scenario(args.scenario), args.timeout)
    except (DebuggerTransportError, RuntimeError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    raise SystemExit(main())
