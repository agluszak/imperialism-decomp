"""Observe pending newspaper-event insertion order in retail and the recomp."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import time

from tools.runtime.debug.mi_process import DebuggerTransportError
from tools.runtime.debug.session import GdbSession, StopEvent, is_terminal_stop
from tools.runtime.debug.symbols import LinkerMap
from tools.runtime.display import virtual_display
from tools.runtime.wine import (
    file_identity,
    initialize_wine_prefix,
    prefix_environment,
    prepare_game_sandbox,
    shut_down_wine_prefix,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-msvc500"
RUNTIME_BUILD_DIR = REPO_ROOT / "build-runtime-tests"
RESULT_ROOT = BUILD_DIR / "differential-results"

SHARED_EVENT_QUEUE_OFFSET = 0xEF0
PTR_ARRAY_DATA_OFFSET = 0x04
PTR_ARRAY_SIZE_OFFSET = 0x08
PTR_LIST_RECORD_SIZE_OFFSET = 0x14
NEWS_RECORD_SIZE = 0x10
NATION_JOINED_WAR = 0x1C

RETAIL_CREATE_NEWS_MANAGER = 0x0055B670
RETAIL_INITIALIZE_NEWS_MANAGER = 0x0055B710
RETAIL_ADD_TREATY_EVENT = 0x0055C9F0
RETAIL_READY_PROBE = 0x005D7240
RETAIL_SIM_MANAGER_POINTER = 0x006A20F8

CREATE_NEWS_MANAGER_SYMBOL = "?CreateObject@TNewsMgr@@SGPAVCObject@@XZ"
INITIALIZE_NEWS_MANAGER_SYMBOL = "?InitializeNewsManager@TNewsMgr@@QAEXXZ"
ADD_TREATY_EVENT_SYMBOL = (
    "?AddTreatyEvent@TNewsMgr@@QAEXW4InterNationEventKind@@HHE@Z"
)
READY_PROBE_SYMBOL = "?DispatchTurnEvent@TViewMgr@@UAEXFH@Z"
SIM_MANAGER_POINTER_SYMBOL = "_g_pSimMgr"


@dataclass(frozen=True)
class Trial:
    name: str
    counterparts: tuple[int, ...]


TRIALS = (
    Trial("forward", (1, 2)),
    Trial("reverse", (2, 1)),
    Trial("forward_repeat", (1, 2)),
)


@dataclass(frozen=True)
class BinaryAddresses:
    create_news_manager: int
    initialize_news_manager: int
    add_treaty_event: int
    ready_probe: int
    sim_manager_pointer: int


@dataclass(frozen=True)
class BinaryObservation:
    binary: dict[str, object]
    trials: dict[str, dict[str, object]]


def _require_symbol(linker_map: LinkerMap, name: str) -> int:
    symbol = linker_map.find_decorated(name)
    if symbol is None:
        raise RuntimeError(f"runtime linker map is missing {name}")
    return symbol.address


def runtime_addresses(map_path: Path) -> BinaryAddresses:
    linker_map = LinkerMap.read(map_path)
    return BinaryAddresses(
        create_news_manager=_require_symbol(linker_map, CREATE_NEWS_MANAGER_SYMBOL),
        initialize_news_manager=_require_symbol(
            linker_map, INITIALIZE_NEWS_MANAGER_SYMBOL
        ),
        add_treaty_event=_require_symbol(linker_map, ADD_TREATY_EVENT_SYMBOL),
        ready_probe=_require_symbol(linker_map, READY_PROBE_SYMBOL),
        sim_manager_pointer=_require_symbol(linker_map, SIM_MANAGER_POINTER_SYMBOL),
    )


def _wait_for_breakpoint(
    session: GdbSession, number: str, timeout: float
) -> StopEvent:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stop = session.wait_for_stop(min(1.0, deadline - time.monotonic()))
        if stop is None:
            if session.process.poll() is not None:
                raise RuntimeError("debugged game exited before the injected call returned")
            continue
        if is_terminal_stop(stop):
            raise RuntimeError("debugged game exited before the injected call returned")
        if stop.reason != "breakpoint-hit" or stop.breakpoint_number != number:
            session.capture_stop(f"unexpected-{stop.signal_name or stop.reason}", stop)
            raise RuntimeError(
                f"debugged game stopped unexpectedly: {stop.signal_name or stop.reason}"
            )
        return stop
    session.interrupt_and_capture("pending-news-order-timeout")
    raise RuntimeError("timed out waiting for injected call to return")


def _invoke(
    session: GdbSession,
    address: int,
    arguments: tuple[int, ...] = (),
    receiver: int | None = None,
) -> int:
    stack = int(session.evaluate("$esp"), 0)
    return_address = int(session.evaluate("$eip"), 0)
    call_stack = stack - 4 * (len(arguments) + 1)
    breakpoint = session.set_breakpoint(return_address)
    try:
        session.assign(f"*(unsigned int*)0x{call_stack:08x}", return_address)
        for index, argument in enumerate(arguments):
            session.assign(
                f"*(unsigned int*)0x{call_stack + 4 + index * 4:08x}", argument
            )
        session.assign("$esp", call_stack)
        if receiver is not None:
            session.assign("$ecx", receiver)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_breakpoint(session, breakpoint, 30.0)
        result = int(session.evaluate("$eax"), 0)
        session.assign("$esp", stack)
        return result
    finally:
        session.delete_breakpoint(breakpoint)


def _read_u32(session: GdbSession, address: int) -> int:
    return struct.unpack("<I", session.read_memory(address, 4))[0]


def _require_single_player_simulation(
    session: GdbSession, addresses: BinaryAddresses
) -> None:
    sim_manager = _read_u32(session, addresses.sim_manager_pointer)
    if sim_manager == 0:
        raise RuntimeError("g_pSimMgr is null at the ready probe")
    multiplayer_role = struct.unpack(
        "<i", session.read_memory(sim_manager + 0x44, 4)
    )[0]
    gate_flag = session.read_memory(sim_manager + 0x7A, 1)[0]
    if multiplayer_role != 0:
        raise RuntimeError(
            f"g_pSimMgr multiplayer role is {multiplayer_role}, expected single-player"
        )
    if gate_flag != 0:
        raise RuntimeError(f"g_pSimMgr news gate is {gate_flag}, expected open")


def _capture_queue(session: GdbSession, news_manager: int) -> list[dict[str, int]]:
    queue = _read_u32(session, news_manager + SHARED_EVENT_QUEUE_OFFSET)
    if queue == 0:
        raise RuntimeError("initialized TNewsMgr has no shared event queue")
    record_size = struct.unpack(
        "<h", session.read_memory(queue + PTR_LIST_RECORD_SIZE_OFFSET, 2)
    )[0]
    if record_size != NEWS_RECORD_SIZE:
        raise RuntimeError(
            f"shared event queue record size is {record_size}, expected {NEWS_RECORD_SIZE}"
        )
    count = _read_u32(session, queue + PTR_ARRAY_SIZE_OFFSET)
    if count > 16:
        raise RuntimeError(f"shared event queue has implausible size {count}")
    data = _read_u32(session, queue + PTR_ARRAY_DATA_OFFSET)
    if count != 0 and data == 0:
        raise RuntimeError("nonempty shared event queue has no pointer array")

    records = []
    for index in range(count):
        record = _read_u32(session, data + index * 4)
        if record == 0:
            raise RuntimeError(f"shared event queue entry {index} is null")
        event_kind, subject, nation_mask = struct.unpack(
            "<iii", session.read_memory(record, 12)
        )
        if event_kind != NATION_JOINED_WAR:
            raise RuntimeError(
                f"shared event queue entry {index} has event kind {event_kind:#x}"
            )
        if nation_mask <= 0 or nation_mask & (nation_mask - 1):
            raise RuntimeError(
                f"shared event queue entry {index} has non-singleton nation mask "
                f"{nation_mask:#x}"
            )
        records.append(
            {
                "event_kind": event_kind,
                "subject": subject,
                "counterpart": nation_mask.bit_length() - 1,
            }
        )
    return records


def _run_trial(
    session: GdbSession, addresses: BinaryAddresses, trial: Trial
) -> dict[str, object]:
    news_manager = _invoke(session, addresses.create_news_manager)
    if news_manager == 0:
        raise RuntimeError("TNewsMgr::CreateObject returned null")
    _invoke(
        session,
        addresses.initialize_news_manager,
        receiver=news_manager,
    )
    if _capture_queue(session, news_manager):
        raise RuntimeError("fresh TNewsMgr shared event queue is not empty")

    queue_after_each_insert = []
    for counterpart in trial.counterparts:
        _invoke(
            session,
            addresses.add_treaty_event,
            (NATION_JOINED_WAR, 0, counterpart, 1),
            receiver=news_manager,
        )
        queue_after_each_insert.append(_capture_queue(session, news_manager))
    return {
        "input_counterparts": list(trial.counterparts),
        "queue_after_each_insert": queue_after_each_insert,
    }


def run_binary(
    kind: str,
    executable: Path,
    addresses: BinaryAddresses,
    artifact_dir: Path,
    timeout: float,
) -> BinaryObservation:
    artifact_dir.mkdir(parents=True)
    prefix = artifact_dir / "prefix"
    environment = prefix_environment(prefix)
    display_context = virtual_display(environment, artifact_dir / "xvfb.log")
    display = display_context.__enter__()
    session: GdbSession | None = None
    try:
        initialize_wine_prefix(prefix, environment)
        game_dir, _fixture, asset_manifest = prepare_game_sandbox(
            artifact_dir, executable
        )
        sandbox_executable = game_dir / "Imperialism.exe"
        session = GdbSession(sandbox_executable, game_dir, environment, artifact_dir)
        session.start(auto_continue=False)
        ready_breakpoint = session.set_breakpoint(addresses.ready_probe)
        session.continue_inferior()
        _wait_for_breakpoint(session, ready_breakpoint, timeout)
        session.delete_breakpoint(ready_breakpoint)
        _require_single_player_simulation(session, addresses)

        trials = {
            trial.name: _run_trial(session, addresses, trial) for trial in TRIALS
        }
        return BinaryObservation(
            binary={
                **file_identity(executable),
                "kind": kind,
                "sandbox": file_identity(sandbox_executable),
                "display": display,
                "retail_asset_manifest_sha256": asset_manifest,
            },
            trials=trials,
        )
    finally:
        if session is not None:
            session.terminate_inferior()
            session.close()
        shut_down_wine_prefix(environment)
        display_context.__exit__(None, None, None)
        shutil.rmtree(prefix, ignore_errors=True)


def first_difference(
    left: object, right: object, path: str = "$"
) -> dict[str, object] | None:
    if type(left) is not type(right):
        return {"path": path, "retail": left, "recomp": right}
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return {"path": path, "retail": sorted(left), "recomp": sorted(right)}
        for key in left:
            difference = first_difference(left[key], right[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {"path": path, "retail": left, "recomp": right}
        for index, (left_value, right_value) in enumerate(zip(left, right, strict=True)):
            difference = first_difference(
                left_value, right_value, f"{path}[{index}]"
            )
            if difference is not None:
                return difference
        return None
    if left != right:
        return {"path": path, "retail": left, "recomp": right}
    return None


def _observation_hash(observation: BinaryObservation) -> str:
    payload = json.dumps(
        observation.trials, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def compare_observations(
    retail: BinaryObservation, recomp: BinaryObservation, run_dir: Path
) -> dict[str, object]:
    difference = first_difference(retail.trials, recomp.trials)
    return {
        "evidence_kind": "retail_differential",
        "status": "matched" if difference is None else "diverged",
        "targets": [
            {
                "original_address": f"0x{RETAIL_ADD_TREATY_EVENT:08x}",
                "name": "TNewsMgr::AddTreatyEvent",
            },
            {
                "original_address": "0x004881f0",
                "name": "TSortedPtrList::InsertCopiedRecordSortedByComparator",
            },
            {
                "original_address": "0x00488360",
                "name": "TSortedPtrList::Compare",
            },
        ],
        "trial_count": len(TRIALS),
        "observations": {
            "retail": retail.trials,
            "recomp": recomp.trials,
        },
        "complete_observation_sha256": {
            "retail": _observation_hash(retail),
            "recomp": _observation_hash(recomp),
        },
        "first_divergence": difference,
        "binary_identities": {"retail": retail.binary, "recomp": recomp.binary},
        "excluded_noise": [
            "raw_pointer_values",
            "allocator_addresses",
            "uninitialized_related_nation",
        ],
        "run_dir": str(run_dir),
    }


def run(timeout: float) -> int:
    original = Path(os.environ.get("ORIGINAL_BINARY", "")).resolve()
    recomp = RUNTIME_BUILD_DIR / "Imperialism.exe"
    recomp_map = recomp.with_suffix(".map")
    if not original.is_file():
        raise SystemExit("Set ORIGINAL_BINARY in .env")
    if not recomp.is_file() or not recomp_map.is_file():
        raise SystemExit("missing runtime-test executable/map; run just runtime-test-build")

    run_id = (
        "pending-news-order-"
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    )
    run_dir = RESULT_ROOT / run_id
    run_dir.mkdir(parents=True)
    retail = run_binary(
        "retail",
        original,
        BinaryAddresses(
            RETAIL_CREATE_NEWS_MANAGER,
            RETAIL_INITIALIZE_NEWS_MANAGER,
            RETAIL_ADD_TREATY_EVENT,
            RETAIL_READY_PROBE,
            RETAIL_SIM_MANAGER_POINTER,
        ),
        run_dir / "retail",
        timeout,
    )
    recomp_observation = run_binary(
        "recomp", recomp, runtime_addresses(recomp_map), run_dir / "recomp", timeout
    )
    result = compare_observations(retail, recomp_observation, run_dir)
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (run_dir / "result.json").write_text(serialized, encoding="utf-8")
    (RESULT_ROOT / "pending-news-order.json").write_text(
        serialized, encoding="utf-8"
    )
    print(serialized, end="")
    return 0 if result["status"] == "matched" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    try:
        return run(args.timeout)
    except (DebuggerTransportError, RuntimeError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    raise SystemExit(main())
