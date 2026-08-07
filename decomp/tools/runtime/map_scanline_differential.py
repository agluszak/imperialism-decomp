"""Isolated retail/recomp differential for the TMapMaker region scanline fill."""

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

MAP_WIDTH = 0x6C
MAP_HEIGHT = 0x3C
TILE_SIZE = 0x24
TILE_COUNT = MAP_WIDTH * MAP_HEIGHT
GRID_SIZE = TILE_COUNT * TILE_SIZE
TERRAIN_OFFSET = 0
REGION_OFFSET = 4
WATER_TERRAIN = 5
MAP_MAKER_SIZE = 0x2A8
SEA_SEGMENT_SIZE = 0x18

RETAIL_TARGET = 0x0052B9B0
RETAIL_READY_PROBE = 0x005D7240
RETAIL_OPERATOR_NEW = 0x00606F73
RETAIL_SEGMENTS = 0x006A3900
RETAIL_ASSERT_SUPPRESS = 0x006A3910
RETAIL_MAP_STATE_POINTER = 0x006A43D4

TARGET_SYMBOL = "?AssignCityRegionIdsFromOverlayScanlineIntersections@TMapMaker@@QAEXXZ"
READY_PROBE_SYMBOL = "?DispatchTurnEvent@TViewMgr@@UAEXFH@Z"
OPERATOR_NEW_SYMBOL = "??2@YAPAXI@Z"
SEGMENTS_SYMBOL = "?g_regionBorderLinkTable_006a3900@@3VSeaSegmentStretch@@A"
ASSERT_SUPPRESS_SYMBOL = "?g_bOverlayScanlineFillAssertSuppressed@@3HA"
MAP_STATE_POINTER_SYMBOL = "_g_pGlobalMapState"


@dataclass(frozen=True)
class Segment:
    x0: int
    y0: int
    x1: int
    y1: int
    region_a: int
    region_b: int
    angle: int
    wraps: int = 0

    def encode(self) -> bytes:
        return struct.pack(
            "<hhhhIIhhhBB",
            self.x0,
            self.y0,
            self.x1,
            self.y1,
            self.x0 + self.y0 * 0xD8,
            self.x1 + self.y1 * 0xD8,
            self.region_a,
            self.region_b,
            self.angle,
            self.wraps,
            0,
        )


@dataclass(frozen=True)
class Fixture:
    name: str
    segments: tuple[Segment, ...]


@dataclass(frozen=True)
class BinaryAddresses:
    target: int
    ready_probe: int
    operator_new: int
    segments: int
    assert_suppress: int
    map_state_pointer: int


@dataclass(frozen=True)
class BinaryObservation:
    binary: dict[str, object]
    fixtures: dict[str, bytes]


FIXTURES = (
    Fixture(
        "left_boundary_parities",
        (
            Segment(0, 0, 0, MAP_HEIGHT, 1, 2, 0x1000),
            Segment(1, 0, 1, MAP_HEIGHT, 3, 4, 0x2000),
        ),
    ),
    Fixture(
        "slopes_and_cell_boundaries",
        (
            Segment(1, 0, 1, MAP_HEIGHT, 1, 2, 0x1000),
            Segment(18, 0, 72, MAP_HEIGHT, 3, 4, 0x2000),
            Segment(108, 0, 54, MAP_HEIGHT, 5, 6, 0x7000),
        ),
    ),
    Fixture(
        "shared_start_overlap",
        (
            Segment(1, 0, 1, MAP_HEIGHT, 1, 2, 0x1000),
            Segment(30, 0, 78, MAP_HEIGHT, 7, 8, 0x6000),
            Segment(30, 0, 6, MAP_HEIGHT, 9, 10, 0x2000),
        ),
    ),
    Fixture(
        "shared_end_overlap",
        (
            Segment(1, 0, 1, MAP_HEIGHT, 1, 2, 0x1000),
            Segment(18, 0, 54, MAP_HEIGHT, 11, 12, 0x2000),
            Segment(90, 0, 54, MAP_HEIGHT, 13, 14, 0x7000),
        ),
    ),
    Fixture(
        "horizontal_wrap",
        (
            Segment(1, 0, 1, MAP_HEIGHT, 1, 2, 0x1000),
            Segment(200, 0, 10, MAP_HEIGHT, 15, 16, 0x7000, 1),
        ),
    ),
)


def _require_symbol(linker_map: LinkerMap, name: str) -> int:
    symbol = linker_map.find_decorated(name)
    if symbol is None:
        raise RuntimeError(f"runtime linker map is missing {name}")
    return symbol.address


def runtime_addresses(map_path: Path) -> BinaryAddresses:
    linker_map = LinkerMap.read(map_path)
    return BinaryAddresses(
        target=_require_symbol(linker_map, TARGET_SYMBOL),
        ready_probe=_require_symbol(linker_map, READY_PROBE_SYMBOL),
        operator_new=_require_symbol(linker_map, OPERATOR_NEW_SYMBOL),
        segments=_require_symbol(linker_map, SEGMENTS_SYMBOL),
        assert_suppress=_require_symbol(linker_map, ASSERT_SUPPRESS_SYMBOL),
        map_state_pointer=_require_symbol(linker_map, MAP_STATE_POINTER_SYMBOL),
    )


def initial_grid() -> bytes:
    tile = bytearray(TILE_SIZE)
    tile[TERRAIN_OFFSET] = WATER_TERRAIN
    tile[REGION_OFFSET] = 0xCC
    return bytes(tile) * TILE_COUNT


def region_array(grid: bytes) -> bytes:
    if len(grid) != GRID_SIZE:
        raise ValueError(f"tile grid has {len(grid)} bytes, expected {GRID_SIZE}")
    return bytes(grid[index * TILE_SIZE + REGION_OFFSET] for index in range(TILE_COUNT))


def first_region_difference(retail: bytes, recomp: bytes) -> dict[str, int] | None:
    if len(retail) != TILE_COUNT or len(recomp) != TILE_COUNT:
        raise ValueError("region arrays must cover the complete map")
    for index, (left, right) in enumerate(zip(retail, recomp, strict=True)):
        if left != right:
            return {
                "write_index": index,
                "row": index // MAP_WIDTH,
                "column": index % MAP_WIDTH,
                "retail": left,
                "recomp": right,
            }
    return None


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
    session.interrupt_and_capture("map-scanline-timeout")
    raise RuntimeError("timed out waiting for injected call to return")


def _invoke_operator_new(session: GdbSession, address: int, size: int) -> int:
    stack = int(session.evaluate("$esp"), 0)
    return_address = int(session.evaluate("$eip"), 0)
    return_breakpoint = session.set_breakpoint(return_address)
    try:
        session.assign(f"*(unsigned int*)0x{stack - 4:08x}", size)
        session.assign(f"*(unsigned int*)0x{stack - 8:08x}", return_address)
        session.assign("$esp", stack - 8)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_breakpoint(session, return_breakpoint, 30.0)
        result = int(session.evaluate("$eax"), 0)
        session.assign("$esp", stack)
        if result == 0:
            raise RuntimeError(f"operator new returned null for {size} bytes")
        return result
    finally:
        session.delete_breakpoint(return_breakpoint)


def _invoke_thiscall(session: GdbSession, address: int, receiver: int) -> None:
    stack = int(session.evaluate("$esp"), 0)
    return_address = int(session.evaluate("$eip"), 0)
    return_breakpoint = session.set_breakpoint(return_address)
    try:
        session.assign(f"*(unsigned int*)0x{stack - 4:08x}", return_address)
        session.assign("$esp", stack - 4)
        session.assign("$ecx", receiver)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_breakpoint(session, return_breakpoint, 30.0)
        session.assign("$esp", stack)
    finally:
        session.delete_breakpoint(return_breakpoint)


def _grid_initializer_code(grid: int) -> bytes:
    """Return a tiny harness-only x86 loop that initializes relevant tile bytes."""
    return (
        b"\xb9" + struct.pack("<I", TILE_COUNT)
        + b"\xbf" + struct.pack("<I", grid)
        + b"\xc6\x07" + bytes((WATER_TERRAIN,))
        + b"\xc6\x47\x04\xcc"
        + b"\x83\xc7\x24\x49\x75\xf3\xc3"
    )


def _region_gather_code(grid: int, output: int) -> bytes:
    """Return a tiny harness-only x86 loop that packs tile[4] into one array."""
    return (
        b"\xb9" + struct.pack("<I", TILE_COUNT)
        + b"\xbe" + struct.pack("<I", grid + REGION_OFFSET)
        + b"\xbf" + struct.pack("<I", output)
        + b"\x8a\x06\x88\x07\x83\xc6\x24\x47\x49\x75\xf5\xc3"
    )


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

        map_maker = _invoke_operator_new(session, addresses.operator_new, MAP_MAKER_SIZE)
        grid = _invoke_operator_new(session, addresses.operator_new, GRID_SIZE)
        segment_storage = _invoke_operator_new(
            session,
            addresses.operator_new,
            max(len(fixture.segments) for fixture in FIXTURES) * SEA_SEGMENT_SIZE,
        )
        scratch = _invoke_operator_new(session, addresses.operator_new, 0x2100)
        map_state = _invoke_operator_new(session, addresses.operator_new, 0x24)
        initializer = scratch + 0x1F00
        gather = scratch + 0x2000
        session.write_memory(map_maker, bytes(MAP_MAKER_SIZE))
        session.assign(f"*(unsigned int*)0x{map_maker + 8:08x}", grid)
        session.assign(f"*(unsigned int*)0x{addresses.segments + 4:08x}", segment_storage)
        session.assign(f"*(int*)0x{addresses.assert_suppress:08x}", 1)
        session.write_memory(map_state, bytes(0x24))
        session.assign(
            f"*(unsigned int*)0x{addresses.map_state_pointer:08x}", map_state
        )

        observations: dict[str, bytes] = {}
        for fixture in FIXTURES:
            encoded_segments = b"".join(segment.encode() for segment in fixture.segments)
            session.write_memory(segment_storage, encoded_segments)
            session.assign(f"*(int*)0x{addresses.segments + 8:08x}", len(fixture.segments))
            session.assign(f"*(int*)0x{addresses.segments + 12:08x}", len(fixture.segments))
            session.write_memory(initializer, _grid_initializer_code(grid))
            _invoke_thiscall(session, initializer, map_maker)
            _invoke_thiscall(session, addresses.target, map_maker)
            session.write_memory(gather, _region_gather_code(grid, scratch))
            _invoke_thiscall(session, gather, map_maker)
            observations[fixture.name] = session.read_memory(scratch, TILE_COUNT)

        return BinaryObservation(
            binary={
                **file_identity(executable),
                "kind": kind,
                "sandbox": file_identity(sandbox_executable),
                "display": display,
                "retail_asset_manifest_sha256": asset_manifest,
            },
            fixtures=observations,
        )
    finally:
        if session is not None:
            session.terminate_inferior()
            session.close()
        shut_down_wine_prefix(environment)
        display_context.__exit__(None, None, None)
        shutil.rmtree(prefix, ignore_errors=True)


def compare_observations(
    retail: BinaryObservation, recomp: BinaryObservation, run_dir: Path
) -> dict[str, object]:
    fixture_results = []
    first_divergence = None
    for fixture in FIXTURES:
        retail_regions = retail.fixtures[fixture.name]
        recomp_regions = recomp.fixtures[fixture.name]
        difference = first_region_difference(retail_regions, recomp_regions)
        fixture_results.append(
            {
                "fixture": fixture.name,
                "segment_count": len(fixture.segments),
                "complete_region_array_sha256": {
                    "retail": hashlib.sha256(retail_regions).hexdigest(),
                    "recomp": hashlib.sha256(recomp_regions).hexdigest(),
                },
                "status": "matched" if difference is None else "diverged",
                "first_divergent_scanline_write": difference,
            }
        )
        if difference is not None and first_divergence is None:
            first_divergence = {"fixture": fixture.name, **difference}
    return {
        "format_version": 1,
        "evidence_kind": "retail_differential",
        "target": {
            "original_address": f"0x{RETAIL_TARGET:08x}",
            "name": "TMapMaker::AssignCityRegionIdsFromOverlayScanlineIntersections",
        },
        "status": "matched" if first_divergence is None else "diverged",
        "fixtures": fixture_results,
        "first_divergence": first_divergence,
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

    run_id = f"map-scanline-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = RESULT_ROOT / run_id
    run_dir.mkdir(parents=True)
    retail = run_binary(
        "retail",
        original,
        BinaryAddresses(
            RETAIL_TARGET,
            RETAIL_READY_PROBE,
            RETAIL_OPERATOR_NEW,
            RETAIL_SEGMENTS,
            RETAIL_ASSERT_SUPPRESS,
            RETAIL_MAP_STATE_POINTER,
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
    (RESULT_ROOT / "map-scanline.json").write_text(serialized, encoding="utf-8")
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
