"""Isolated retail/recomp differential for the TurnEvent2 array packet codecs."""

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

HEADER_SIZE = 0x24
GAME_FLOW_SIZE = 0xF4
PENDING_NATION_OFFSET = 0xF0

RETAIL_BUILDERS = {1: 0x00544840, 2: 0x005449B0, 4: 0x00544B30}
RETAIL_DECODER = 0x00544CD0
RETAIL_READY_PROBE = 0x005D7240
RETAIL_OPERATOR_NEW = 0x00606F73
RETAIL_GAME_FLOW_POINTER = 0x006A43C8

BUILDER_SYMBOLS = {
    1: "?BuildTurnEvent2ByteArraySyncPacketDeltaOrFull@@YAPAUTurnEvent2SyncPacket@@IPAE0@Z",
    2: "?BuildTurnEvent2ArraySyncPacketDeltaOrFull@@YAPAUTurnEvent2SyncPacket@@IPAF0@Z",
    4: "?BuildTurnEvent2IntArraySyncPacketDeltaOrFull@@YAPAUTurnEvent2SyncPacket@@HPAH0@Z",
}
DECODER_SYMBOL = "?ApplyEncodedDeltaPayloadToBufferByMode@TurnEvent2SyncPacket@@QAEXPAX@Z"
READY_PROBE_SYMBOL = "?DispatchTurnEvent@TViewMgr@@UAEXFH@Z"
OPERATOR_NEW_SYMBOL = "??2@YAPAXI@Z"
GAME_FLOW_POINTER_SYMBOL = "_g_pGameFlowState"


@dataclass(frozen=True)
class BuilderFixture:
    name: str
    width: int
    current: tuple[int, ...]
    baseline: tuple[int, ...] | None


@dataclass(frozen=True)
class DecoderFixture:
    name: str
    mode: int
    payload: bytes
    initial: bytes


@dataclass(frozen=True)
class BinaryAddresses:
    builders: dict[int, int]
    decoder: int
    ready_probe: int
    operator_new: int
    game_flow_pointer: int


@dataclass(frozen=True)
class BinaryObservation:
    binary: dict[str, object]
    builders: dict[str, dict[str, object]]
    decoders: dict[str, str]


def _changed_values(count: int, indices: tuple[int, ...], width: int) -> tuple[int, ...]:
    values = [index * 17 + 3 for index in range(count)]
    mask = (1 << (width * 8)) - 1
    for index in indices:
        values[index] = (values[index] ^ (0xA5A55A5A & mask)) & mask
    return tuple(values)


def build_builder_fixtures() -> tuple[BuilderFixture, ...]:
    fixtures = []
    for width in (1, 2, 4):
        for count in (0, 1, 2, 3, 4, 6, 8, 12):
            baseline = tuple(index * 17 + 3 for index in range(count))
            fixtures.append(BuilderFixture(f"w{width}-n{count}-null", width, baseline, None))
            fixtures.append(BuilderFixture(f"w{width}-n{count}-same", width, baseline, baseline))
            if count:
                fixtures.append(
                    BuilderFixture(
                        f"w{width}-n{count}-first", width, _changed_values(count, (0,), width), baseline
                    )
                )
                fixtures.append(
                    BuilderFixture(
                        f"w{width}-n{count}-last",
                        width,
                        _changed_values(count, (count - 1,), width),
                        baseline,
                    )
                )
                dense = tuple(range((count + 1) // 2))
                fixtures.append(
                    BuilderFixture(
                        f"w{width}-n{count}-dense", width, _changed_values(count, dense, width), baseline
                    )
                )
                record_size = width + 2
                full_size = count * width
                if full_size % record_size == 0:
                    equal_count = full_size // record_size
                    for label, differing in (
                        ("threshold-below", max(0, equal_count - 1)),
                        ("threshold-equal", equal_count),
                        ("threshold-above", min(count, equal_count + 1)),
                    ):
                        fixtures.append(
                            BuilderFixture(
                                f"w{width}-n{count}-{label}",
                                width,
                                _changed_values(count, tuple(range(differing)), width),
                                baseline,
                            )
                        )
    return tuple(fixtures)


def _entry(mode: int, index: int, value: int) -> bytes:
    if mode == 1:
        return struct.pack("<HB", index, value)
    if mode == 2:
        return struct.pack("<Hh", index, value)
    return struct.pack("<Hi", index, value)


def build_decoder_fixtures() -> tuple[DecoderFixture, ...]:
    fixtures = [
        DecoderFixture("mode0-empty", 0, b"", bytes(range(32))),
        DecoderFixture("mode0-copy", 0, bytes((9, 8, 7, 6, 5)), bytes(range(32))),
        DecoderFixture("invalid-mode", 4, bytes((1, 2, 3, 4, 5, 6)), bytes(range(32))),
    ]
    for mode, width in ((1, 1), (2, 2), (3, 4)):
        record = _entry(mode, 3, 0x55 if width == 1 else 0x1234 if width == 2 else 0x12345678)
        second = _entry(mode, 7, 0x66 if width == 1 else -1234 if width == 2 else -1234567)
        for remainder in range(len(record)):
            fixtures.append(
                DecoderFixture(
                    f"mode{mode}-one-rem{remainder}",
                    mode,
                    record + bytes(range(1, remainder + 1)),
                    bytes(range(64)),
                )
            )
        fixtures.append(DecoderFixture(f"mode{mode}-two", mode, record + second, bytes(range(64))))
    return tuple(fixtures)


BUILDER_FIXTURES = build_builder_fixtures()
DECODER_FIXTURES = build_decoder_fixtures()


def _require_symbol(linker_map: LinkerMap, name: str) -> int:
    symbol = linker_map.find_decorated(name)
    if symbol is None:
        raise RuntimeError(f"runtime linker map is missing {name}")
    return symbol.address


def runtime_addresses(map_path: Path) -> BinaryAddresses:
    linker_map = LinkerMap.read(map_path)
    return BinaryAddresses(
        builders={width: _require_symbol(linker_map, name) for width, name in BUILDER_SYMBOLS.items()},
        decoder=_require_symbol(linker_map, DECODER_SYMBOL),
        ready_probe=_require_symbol(linker_map, READY_PROBE_SYMBOL),
        operator_new=_require_symbol(linker_map, OPERATOR_NEW_SYMBOL),
        game_flow_pointer=_require_symbol(linker_map, GAME_FLOW_POINTER_SYMBOL),
    )


def _wait_for_breakpoint(session: GdbSession, number: str, timeout: float) -> StopEvent:
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
    session.interrupt_and_capture("turn-event2-codec-timeout")
    raise RuntimeError("timed out waiting for injected call to return")


def _invoke(
    session: GdbSession,
    address: int,
    arguments: tuple[int, ...],
    receiver: int | None = None,
) -> int:
    stack = int(session.evaluate("$esp"), 0)
    return_address = int(session.evaluate("$eip"), 0)
    call_stack = stack - 4 * (len(arguments) + 1)
    breakpoint = session.set_breakpoint(return_address)
    try:
        session.assign(f"*(unsigned int*)0x{call_stack:08x}", return_address)
        for index, argument in enumerate(arguments):
            session.assign(f"*(unsigned int*)0x{call_stack + 4 + index * 4:08x}", argument)
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


def _allocate(session: GdbSession, address: int, size: int) -> int:
    result = _invoke(session, address, (size,))
    if result == 0:
        raise RuntimeError(f"operator new returned null for {size} bytes")
    return result


def _encode(values: tuple[int, ...], width: int) -> bytes:
    if width == 1:
        return bytes(value & 0xFF for value in values)
    code = "h" if width == 2 else "i"
    sign_bit = 1 << (width * 8 - 1)
    modulus = 1 << (width * 8)
    return b"".join(
        struct.pack("<" + code, value - modulus if value & sign_bit else value)
        for value in values
    )


def _packet_observation(packet: bytes) -> dict[str, object]:
    defined = bytearray(packet)
    for start, end in ((0x10, 0x18), (0x1A, 0x21), (0x22, 0x24)):
        defined[start:end] = bytes(end - start)
    return {
        "length": len(packet),
        "mode": packet[0x21],
        "defined_wire_bytes": bytes(defined).hex(),
        "defined_wire_sha256": hashlib.sha256(defined).hexdigest(),
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
        game_dir, _fixture, asset_manifest = prepare_game_sandbox(artifact_dir, executable)
        sandbox_executable = game_dir / "Imperialism.exe"
        session = GdbSession(sandbox_executable, game_dir, environment, artifact_dir)
        session.start(auto_continue=False)
        ready_breakpoint = session.set_breakpoint(addresses.ready_probe)
        session.continue_inferior()
        _wait_for_breakpoint(session, ready_breakpoint, timeout)
        session.delete_breakpoint(ready_breakpoint)

        game_flow = _allocate(session, addresses.operator_new, GAME_FLOW_SIZE)
        session.write_memory(game_flow, bytes(GAME_FLOW_SIZE))
        session.assign(f"*(short*)0x{game_flow + PENDING_NATION_OFFSET:08x}", 6)
        session.assign(f"*(unsigned int*)0x{addresses.game_flow_pointer:08x}", game_flow)
        current = _allocate(session, addresses.operator_new, 0x100)
        baseline = _allocate(session, addresses.operator_new, 0x100)
        packet_storage = _allocate(session, addresses.operator_new, 0x100)
        output = _allocate(session, addresses.operator_new, 0x100)

        builder_observations = {}
        for fixture in BUILDER_FIXTURES:
            current_bytes = _encode(fixture.current, fixture.width)
            baseline_bytes = (
                _encode(fixture.baseline, fixture.width) if fixture.baseline is not None else b""
            )
            session.write_memory(current, current_bytes or b"\0")
            if fixture.baseline is not None:
                session.write_memory(baseline, baseline_bytes or b"\0")
            packet = _invoke(
                session,
                addresses.builders[fixture.width],
                (len(fixture.current), current, baseline if fixture.baseline is not None else 0),
            )
            message_length = struct.unpack("<I", session.read_memory(packet + 0x0C, 4))[0]
            packet_bytes = session.read_memory(packet, message_length)
            builder_observations[fixture.name] = _packet_observation(packet_bytes)

        decoder_observations = {}
        for fixture in DECODER_FIXTURES:
            packet_size = HEADER_SIZE + len(fixture.payload)
            header = bytearray(packet_size)
            struct.pack_into("<I", header, 0x0C, packet_size)
            header[0x21] = fixture.mode
            header[HEADER_SIZE:] = fixture.payload
            session.write_memory(packet_storage, bytes(header))
            session.write_memory(output, fixture.initial)
            _invoke(session, addresses.decoder, (output,), receiver=packet_storage)
            decoder_observations[fixture.name] = session.read_memory(output, len(fixture.initial)).hex()

        return BinaryObservation(
            binary={
                **file_identity(executable),
                "kind": kind,
                "sandbox": file_identity(sandbox_executable),
                "display": display,
                "retail_asset_manifest_sha256": asset_manifest,
            },
            builders=builder_observations,
            decoders=decoder_observations,
        )
    finally:
        if session is not None:
            session.terminate_inferior()
            session.close()
        shut_down_wine_prefix(environment)
        display_context.__exit__(None, None, None)
        shutil.rmtree(prefix, ignore_errors=True)


def first_difference(retail: BinaryObservation, recomp: BinaryObservation) -> dict[str, object] | None:
    for fixture in BUILDER_FIXTURES:
        left = retail.builders[fixture.name]
        right = recomp.builders[fixture.name]
        if left != right:
            left_bytes = bytes.fromhex(str(left["defined_wire_bytes"]))
            right_bytes = bytes.fromhex(str(right["defined_wire_bytes"]))
            for index, (left_byte, right_byte) in enumerate(zip(left_bytes, right_bytes)):
                if left_byte != right_byte:
                    return {
                        "fixture": fixture.name,
                        "field": "packet_bytes",
                        "byte_offset": index,
                        "retail": left_byte,
                        "recomp": right_byte,
                    }
            return {"fixture": fixture.name, "field": "packet", "retail": left, "recomp": right}
    for fixture in DECODER_FIXTURES:
        left = bytes.fromhex(retail.decoders[fixture.name])
        right = bytes.fromhex(recomp.decoders[fixture.name])
        if left != right:
            for index, (left_byte, right_byte) in enumerate(zip(left, right)):
                if left_byte != right_byte:
                    return {
                        "fixture": fixture.name,
                        "field": "decoded_buffer",
                        "byte_offset": index,
                        "retail": left_byte,
                        "recomp": right_byte,
                    }
    return None


def _hash_observation(observation: BinaryObservation) -> str:
    payload = json.dumps(
        {"builders": observation.builders, "decoders": observation.decoders},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def compare_observations(
    retail: BinaryObservation, recomp: BinaryObservation, run_dir: Path
) -> dict[str, object]:
    difference = first_difference(retail, recomp)
    return {
        "format_version": 1,
        "evidence_kind": "retail_differential",
        "status": "matched" if difference is None else "diverged",
        "builder_fixture_count": len(BUILDER_FIXTURES),
        "decoder_fixture_count": len(DECODER_FIXTURES),
        "first_divergence": difference,
        "complete_observation_sha256": {
            "retail": _hash_observation(retail),
            "recomp": _hash_observation(recomp),
        },
        "binary_identities": {"retail": retail.binary, "recomp": recomp.binary},
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

    run_id = f"turn-event2-codec-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = RESULT_ROOT / run_id
    run_dir.mkdir(parents=True)
    retail = run_binary(
        "retail",
        original,
        BinaryAddresses(
            RETAIL_BUILDERS,
            RETAIL_DECODER,
            RETAIL_READY_PROBE,
            RETAIL_OPERATOR_NEW,
            RETAIL_GAME_FLOW_POINTER,
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
    (RESULT_ROOT / "turn-event2-codec.json").write_text(serialized, encoding="utf-8")
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
