"""Compare a native recomp checkpoint with a narrow retail GDB observation.

This is the retail-vs-recomp GDB checkpoint runner. It is separate from the
C++→Rust process-isolated differential in the Rust testkit.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import time

from tools.runtime.checkpoints import (
    SCHEMAS,
    first_checkpoint_difference,
    normalize_native_combined_map,
    normalize_retail_combined_map,
    validate_checkpoint,
)
from tools.runtime.debug.binary import direct_call_target_after
from tools.runtime.debug.mi_process import DebuggerTransportError
from tools.runtime.debug.session import GdbSession, is_terminal_stop
from tools.runtime.display import virtual_display
from tools.runtime.runner import RunRequest, RuntimeRunner
from tools.runtime.wine import (
    file_identity,
    initialize_wine_prefix,
    prefix_environment,
    prepare_game_sandbox,
    shut_down_wine_prefix,
    windows_path,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
FIXTURE_DIR = REPO_ROOT.parent / "fixtures" / "retail"
RESULT_DIR = BUILD_DIR / "differential-results"


@dataclass(frozen=True)
class Probe:
    probe_id: str
    original_address: int
    fields: dict[str, "FieldCapture"]


@dataclass(frozen=True)
class FieldCapture:
    expression: str
    normalize: str = "int"


@dataclass(frozen=True)
class ProbeWait:
    probe: str
    field: str
    equals: int


@dataclass(frozen=True)
class DeferredShellAction:
    owner_address: int
    after_call_to: int
    replay_after: ProbeWait
    rewrite_probe: str
    rewrite_field: str
    rewrite_from: int
    rewrite_to: int
    rewrite_expression: str
    rewrite_action_id: str


@dataclass(frozen=True)
class Checkpoint:
    probe: str
    field: str
    equals: int
    checkpoint_id: str
    fields: dict[str, FieldCapture]


@dataclass(frozen=True)
class Scenario:
    name: str
    native_test: str
    action_id: str
    fixture: Path
    probes: tuple[Probe, ...]
    terminal_checkpoint: Checkpoint
    timeout_seconds: float
    start_action: DeferredShellAction


@dataclass(frozen=True)
class Trace:
    metadata: dict
    records: list[dict]


def _load_save_to_map_scenario(fixture: Path) -> Scenario:
    """Embedded retail-vs-recomp GDB checkpoint scenario."""
    production_orders = {
            "production_order_00": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1dc)', 's16'),
            "production_order_01": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1de)', 's16'),
            "production_order_02": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e0)', 's16'),
            "production_order_03": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e2)', 's16'),
            "production_order_04": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e4)', 's16'),
            "production_order_05": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e6)', 's16'),
            "production_order_06": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1e8)', 's16'),
            "production_order_07": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1ea)', 's16'),
            "production_order_08": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1ec)', 's16'),
            "production_order_09": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1ee)', 's16'),
            "production_order_10": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f0)', 's16'),
            "production_order_11": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f2)', 's16'),
            "production_order_12": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f4)', 's16'),
            "production_order_13": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f6)', 's16'),
            "production_order_14": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1f8)', 's16'),
            "production_order_15": FieldCapture('*(short*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x1fa)', 's16'),
    }
    production_flags = {
            "production_flag_00": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21c)', 'int'),
            "production_flag_01": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21d)', 'int'),
            "production_flag_02": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21e)', 'int'),
            "production_flag_03": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x21f)', 'int'),
            "production_flag_04": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x220)', 'int'),
            "production_flag_05": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x221)', 'int'),
            "production_flag_06": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x222)', 'int'),
            "production_flag_07": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x223)', 'int'),
            "production_flag_08": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x224)', 'int'),
            "production_flag_09": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x225)', 'int'),
            "production_flag_10": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x226)', 'int'),
            "production_flag_11": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x227)', 'int'),
            "production_flag_12": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x228)', 'int'),
            "production_flag_13": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x229)', 'int'),
            "production_flag_14": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x22a)', 'int'),
            "production_flag_15": FieldCapture('*(unsigned char*)(*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894) + 0x22b)', 'int'),
    }
    checkpoint_fields = {
            "turn_event": FieldCapture('*(short*)(*(unsigned int*)0x006a21bc + 4)', 'u16'),
            "combined_map_view_present": FieldCapture('*(unsigned int*)(*(unsigned int*)0x006a21bc + 0xf0)', 'bool'),
            "active_nation": FieldCapture('*(short*)(*(unsigned int*)0x006a20f8 + 0x2e)', 's16'),
            "economic_turn": FieldCapture('*(short*)(*(unsigned int*)0x006a20f8 + 0x2c)', 's16'),
            "map_present": FieldCapture('*(unsigned int*)0x006a43d4', 'bool'),
            "map_wrap": FieldCapture('*(char*)(*(unsigned int*)0x006a43d4 + 0x20)', 'int'),
            "city_present": FieldCapture('*(unsigned int*)(*(unsigned int*)(0x006a4370 + (*(short*)(*(unsigned int*)0x006a20f8 + 0x2e))*4) + 0x894)', 'bool'),
    }
    checkpoint_fields.update(production_orders)
    checkpoint_fields.update(production_flags)
    return Scenario(
        name="load_save_to_map",
        native_test="load_saved_game",
        action_id="combined_map.enter",
        fixture=fixture,
        probes=(
            Probe(
                probe_id="turn_event.dispatch",
                original_address=0x005d7240,
                fields={
                    "event": FieldCapture("*(short*)($esp+4)", "u16"),
                    "payload": FieldCapture("*(int*)($esp+8)", "u32"),
                },
            ),
        ),
        terminal_checkpoint=Checkpoint(
            probe="turn_event.dispatch",
            field="event",
            equals=0x07dd,
            checkpoint_id="combined_map.ready",
            fields=checkpoint_fields,
        ),
        timeout_seconds=90.0,
        start_action=DeferredShellAction(
            owner_address=0x00412dc0,
            after_call_to=0x00415760,
            replay_after=ProbeWait(probe="turn_event.dispatch", field="event", equals=0x11f8),
            rewrite_probe="turn_event.dispatch",
            rewrite_field="event",
            rewrite_from=0x11f8,
            rewrite_to=0x05dc,
            rewrite_expression="*(short*)($esp+4)",
            rewrite_action_id="opening_cinematic.skip_to_main_menu",
        ),
    )


def load_scenario(name: str) -> Scenario:
    if name != "load_save_to_map":
        raise SystemExit(f"unknown retail checkpoint differential scenario {name!r}")
    fixture_root = Path(os.environ.get("IMPERIALISM_SAVE_FIXTURES", FIXTURE_DIR))
    fixture = fixture_root / "beginning_of_game.imp"
    if not fixture.is_file():
        raise SystemExit(f"missing differential fixture {fixture}")
    scenario = _load_save_to_map_scenario(fixture)
    schema = SCHEMAS.get(scenario.terminal_checkpoint.checkpoint_id)
    if schema is None:
        raise SystemExit("unknown differential checkpoint combined_map.ready")
    if scenario.action_id != schema.action_id:
        raise SystemExit(
            f"checkpoint {schema.checkpoint_id!r} requires action {schema.action_id!r}"
        )
    if scenario.native_test != schema.native_test:
        raise SystemExit(
            f"checkpoint {schema.checkpoint_id!r} requires native test {schema.native_test!r}"
        )
    return scenario

def first_divergence(original: list[dict], recomp: list[dict]) -> dict | None:
    def key(record: dict) -> tuple[str, int]:
        return str(record["probe"]), int(record["occurrence"])

    original_by_key = {key(record): record for record in original}
    recomp_by_key = {key(record): record for record in recomp}
    keys = list(original_by_key)
    keys.extend(key_value for key_value in recomp_by_key if key_value not in original_by_key)
    last_equal: dict | None = None
    for probe, occurrence in keys:
        semantic_key = {"probe": probe, "occurrence": occurrence}
        left = original_by_key.get((probe, occurrence))
        right = recomp_by_key.get((probe, occurrence))
        left_fields = left.get("fields") if left is not None else None
        right_fields = right.get("fields") if right is not None else None
        if left_fields != right_fields:
            if left is None:
                mismatch_kind = "missing_original"
            elif right is None:
                mismatch_kind = "missing_recomp"
            else:
                mismatch_kind = "field_mismatch"
            return {
                "semantic_key": semantic_key,
                "kind": mismatch_kind,
                "original": left,
                "recomp": right,
                "last_equal_checkpoint": last_equal,
            }
        last_equal = semantic_key
    return None


def _write_trace(path: Path, metadata: dict, records: list[dict]) -> None:
    path.write_text(
        json.dumps({"type": "trace_metadata", **metadata}, sort_keys=True)
        + "\n"
        + "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _normalize_value(raw: str, normalization: str) -> int | str:
    numeric_text = raw if normalization == "string" else raw.split(maxsplit=1)[0]
    try:
        value = int(numeric_text, 0)
    except ValueError:
        return raw.strip() if normalization == "string" else raw
    if normalization == "u16":
        return value & 0xFFFF
    if normalization == "s16":
        value &= 0xFFFF
        return value - 0x10000 if value & 0x8000 else value
    if normalization == "u32":
        return value & 0xFFFFFFFF
    if normalization == "bool":
        return value != 0
    if normalization not in {"int", "pointer"}:
        raise ValueError(f"unknown differential field normalization {normalization!r}")
    return value


def _capture_fields(session: GdbSession, probe: Probe) -> dict[str, int | str]:
    fields: dict[str, int | str] = {}
    for name, capture in probe.fields.items():
        fields[name] = _normalize_value(
            session.evaluate(capture.expression), capture.normalize
        )
    return fields


def run_binary(
    scenario: Scenario,
    kind: str,
    executable: Path,
    addresses: dict[str, int],
    control_addresses: dict[str, int],
    run_dir: Path,
    timeout_seconds: float,
) -> Trace:
    artifact_dir = run_dir / kind
    artifact_dir.mkdir(parents=True, exist_ok=True)
    prefix = artifact_dir / "prefix"
    environment = prefix_environment(prefix)
    display_context = virtual_display(environment, artifact_dir / "xvfb.log")
    display = display_context.__enter__()
    try:
        initialize_wine_prefix(prefix, environment)
        game_dir, staged_fixture, asset_manifest_sha256 = prepare_game_sandbox(
            artifact_dir, executable, scenario.fixture
        )
    except BaseException:
        display_context.__exit__(None, None, None)
        raise
    if staged_fixture is None:
        raise RuntimeError("differential retail fixture was not staged")
    sandbox_executable = game_dir / "Imperialism.exe"
    fixture_argument = windows_path(staged_fixture, environment)
    session = GdbSession(
        sandbox_executable,
        game_dir,
        environment,
        artifact_dir,
        arguments=(fixture_argument,),
    )
    records: list[dict] = []
    metadata = {
        "scenario": scenario.name,
        "binary_kind": kind,
        "binary": file_identity(executable),
        "sandbox_binary": file_identity(sandbox_executable),
        "fixture": file_identity(scenario.fixture),
        "retail_asset_manifest_sha256": asset_manifest_sha256,
        "display": display,
        "source_assets_read_only": True,
        "status": "running",
    }
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
        terminal_return_number: str | None = None
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
            if role_name == "terminal_checkpoint":
                fields = _capture_fields(
                    session,
                    Probe(
                        scenario.terminal_checkpoint.checkpoint_id,
                        0,
                        scenario.terminal_checkpoint.fields,
                    ),
                )
                records.append(
                    {
                        "type": "checkpoint",
                        "seq": len(records),
                        "probe": scenario.terminal_checkpoint.checkpoint_id,
                        "occurrence": 1,
                        "fields": fields,
                    }
                )
                metadata["status"] = "completed"
                break
            if probe is None:
                raise RuntimeError(f"{kind} probe breakpoint has no probe definition")
            occurrence = occurrences.get(probe.probe_id, 0) + 1
            occurrences[probe.probe_id] = occurrence
            fields = _capture_fields(session, probe)
            record = {
                "type": "checkpoint",
                "seq": len(records),
                "probe": probe.probe_id,
                "occurrence": occurrence,
                "fields": fields,
            }
            records.append(record)
            if (
                probe.probe_id == scenario.start_action.rewrite_probe
                and fields.get(scenario.start_action.rewrite_field)
                == scenario.start_action.rewrite_from
            ):
                session.assign(
                    scenario.start_action.rewrite_expression,
                    scenario.start_action.rewrite_to,
                )
                record["action_id"] = scenario.start_action.rewrite_action_id
                record["effective_event"] = scenario.start_action.rewrite_to
            if (
                deferred_context is not None
                and replay_number is None
                and probe.probe_id == scenario.start_action.replay_after.probe
                and fields.get(scenario.start_action.replay_after.field)
                == scenario.start_action.replay_after.equals
            ):
                replay_address = int(
                    session.evaluate("*(unsigned int*)$esp"), 0
                )
                replay_number = session.set_breakpoint(replay_address)
                breakpoint_roles[replay_number] = ("replay_shell_command", None)
            if (
                probe.probe_id == scenario.terminal_checkpoint.probe
                and fields.get(scenario.terminal_checkpoint.field)
                == scenario.terminal_checkpoint.equals
            ):
                if terminal_return_number is not None:
                    raise RuntimeError(f"{kind} reached terminal event twice")
                terminal_return_address = int(
                    session.evaluate("*(unsigned int*)$esp"), 0
                )
                terminal_return_number = session.set_breakpoint(terminal_return_address)
                breakpoint_roles[terminal_return_number] = ("terminal_checkpoint", None)
            session.continue_inferior()
        else:
            session.interrupt_and_capture("differential-timeout")
            raise RuntimeError(f"{kind} timed out before the stop checkpoint")
    except Exception as error:
        metadata["status"] = "partial"
        metadata["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if metadata["status"] == "running":
            metadata["status"] = "partial"
        _write_trace(artifact_dir / "trace.ndjson", metadata, records)
        session.close()
        shut_down_wine_prefix(environment)
        display_context.__exit__(None, None, None)
        shutil.rmtree(prefix, ignore_errors=True)
    return Trace(metadata, records)


def run_scenario(scenario: Scenario, timeout: float | None = None) -> int:
    timeout_seconds = scenario.timeout_seconds if timeout is None else timeout
    original_executable = Path(os.environ.get("ORIGINAL_BINARY", "")).resolve()
    if not original_executable.is_file():
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    control_original = {
        "initialization_owner": scenario.start_action.owner_address,
        "before_shell_callee": scenario.start_action.after_call_to,
    }
    run_id = f"{scenario.name}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = RESULT_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    original_trace = run_binary(
        scenario,
        "retail",
        original_executable,
        {probe.probe_id: probe.original_address for probe in scenario.probes},
        control_original,
        run_dir,
        timeout_seconds,
    )
    native_outcome = RuntimeRunner(
        run_dir / "recomp", scenario.fixture.parent
    ).run(
        RunRequest(
            name=scenario.native_test,
            seed=1,
            timeout_seconds=timeout_seconds,
            rerun_seh=False,
            gdb_first=False,
            no_gdb=True,
            require_fixtures=True,
        )
    )
    if native_outcome.exit_code != 0:
        raise RuntimeError(
            f"native recomp driver {scenario.native_test} failed; see "
            f"{run_dir / 'recomp' / (scenario.native_test + '.json')}"
        )
    retail_records = [
        record
        for record in original_trace.records
        if record.get("probe") == scenario.terminal_checkpoint.checkpoint_id
    ]
    if len(retail_records) != 1:
        raise RuntimeError(
            f"retail produced {len(retail_records)} terminal checkpoint records"
        )
    retail_observation = normalize_retail_combined_map(retail_records[0]["fields"])
    recomp_observation = normalize_native_combined_map(native_outcome.result)
    validate_checkpoint(retail_observation)
    validate_checkpoint(recomp_observation)
    divergence = first_checkpoint_difference(retail_observation, recomp_observation)
    result = {
        "scenario": scenario.name,
        "evidence_kind": "retail_differential",
        "status": "matched" if divergence is None else "diverged",
        "execution": {
            "retail": "gdb_checkpoint_tape",
            "recomp": "native_runtime_driver",
        },
        "checkpoint_sequence": [scenario.terminal_checkpoint.checkpoint_id],
        "observations": {
            "retail": retail_observation,
            "recomp": recomp_observation,
        },
        "first_divergence": divergence,
        "binary_identities": {
            "retail": original_trace.metadata["binary"],
            "recomp": native_outcome.result["host"]["provenance"]["runtime_executable"],
        },
        "fixture_identity": original_trace.metadata["fixture"],
        "retail_assets": {
            "source_read_only": original_trace.metadata["source_assets_read_only"],
            "manifest_sha256": original_trace.metadata["retail_asset_manifest_sha256"],
        },
        "excluded_noise": [
            "elapsed_ms",
            "idle_ticks",
            "process_ids",
            "debugger_stop_counts",
            "window_handles",
            "raw_pointer_values",
        ],
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
