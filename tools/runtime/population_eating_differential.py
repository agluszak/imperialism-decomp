"""Isolated retail/recomp differential for population food consumption."""

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
from typing import Iterable

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

POPULATION_SIZE = 0x50
CITY_SIZE = 0x2D4
GREAT_POWER_SIZE = 0x964
LABOR_POOL_SIZE = 0x0C

CITY_OWNER_OFFSET = 0xAC
CITY_CANNED_OFFSET = 0xC4
CITY_GRAIN_OFFSET = 0xD8
CITY_FRUIT_OFFSET = 0xDA
CITY_FISH_OFFSET = 0xDC
CITY_LIVESTOCK_OFFSET = 0xDE
CITY_SUBSTITUTION_OFFSET = 0x06
CITY_STARVATION_OFFSET = 0x08
GREAT_POWER_NEED_TARGET_OFFSET = 0x13C

RETAIL_EAT = 0x004B5ED0
RETAIL_PRETEND = 0x004B6260
RETAIL_READY_PROBE = 0x005D7240
RETAIL_OPERATOR_NEW = 0x00606F73
RETAIL_POPULATION_VTABLE = 0x0064F9B0
RETAIL_CITY_VTABLE = 0x0064F580
RETAIL_LABOR_POOL_VTABLE = 0x0064F540

EAT_SYMBOL = "?Eat@TPopulationMgr@@UAEXXZ"
PRETEND_SYMBOL = "?PretendToEat@TPopulationMgr@@UAEXAAF0@Z"
READY_PROBE_SYMBOL = "?DispatchTurnEvent@TViewMgr@@UAEXFH@Z"
OPERATOR_NEW_SYMBOL = "??2@YAPAXI@Z"
POPULATION_VTABLE_SYMBOL = "??_7TPopulationMgr@@6B@"
CITY_VTABLE_SYMBOL = "??_7TCity@@6B@"
LABOR_POOL_VTABLE_SYMBOL = "??_7TLaborPool@@6B@"


@dataclass(frozen=True)
class Fixture:
    name: str
    population: int
    labor: tuple[int, int, int]
    stocks: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class BinaryAddresses:
    eat: int
    pretend: int
    ready_probe: int
    operator_new: int
    population_vtable: int
    city_vtable: int
    labor_pool_vtable: int


@dataclass(frozen=True)
class ObjectAddresses:
    population: int
    city: int
    owner: int
    baseline: int
    production: int
    pending: int
    outputs: int


@dataclass(frozen=True)
class BinaryObservation:
    binary: dict[str, object]
    fixtures: dict[str, dict[str, object]]


def _labor_compositions(population: int) -> Iterable[tuple[int, int, int]]:
    for low in range(population + 1):
        for medium in range(population - low + 1):
            yield low, medium, population - low - medium


def build_fixtures() -> tuple[Fixture, ...]:
    fixtures = []
    for population in range(5):
        for low, medium, high in _labor_compositions(population):
            for mask in range(32):
                stocks = tuple((mask >> index) & 1 for index in range(5))
                fixtures.append(
                    Fixture(
                        f"small-p{population}-l{low}-{medium}-{high}-s{mask:02x}",
                        population,
                        (low, medium, high),
                        stocks,
                    )
                )

    for population in range(5, 13):
        grain_need = (population + 1) // 2
        fruit_need = (population + 2) // 4
        animal_need = population // 4
        labor_profiles = (
            (population, 0, 0),
            (0, population, 0),
            (0, 0, population),
            (population // 3, population // 3, population - 2 * (population // 3)),
        )
        stock_profiles = (
            (0, 0, 0, 0, 0),
            (0, grain_need, fruit_need, animal_need, 0),
            (1, max(0, grain_need - 1), fruit_need, animal_need, 0),
            (0, grain_need + 1, max(0, fruit_need - 1), animal_need, 0),
            (0, grain_need + 1, fruit_need + 1, 0, 0),
            (0, grain_need, fruit_need, 0, animal_need),
            (0, grain_need, fruit_need, animal_need, 0),
            (grain_need + fruit_need + animal_need, 0, 0, 0, 0),
        )
        for labor_index, labor in enumerate(labor_profiles):
            for stock_index, stocks in enumerate(stock_profiles):
                fixtures.append(
                    Fixture(
                        f"boundary-p{population}-l{labor_index}-s{stock_index}",
                        population,
                        labor,
                        stocks,
                    )
                )
    return tuple(fixtures)


FIXTURES = build_fixtures()


def _require_symbol(linker_map: LinkerMap, name: str) -> int:
    symbol = linker_map.find_decorated(name)
    if symbol is None:
        raise RuntimeError(f"runtime linker map is missing {name}")
    return symbol.address


def runtime_addresses(map_path: Path) -> BinaryAddresses:
    linker_map = LinkerMap.read(map_path)
    return BinaryAddresses(
        eat=_require_symbol(linker_map, EAT_SYMBOL),
        pretend=_require_symbol(linker_map, PRETEND_SYMBOL),
        ready_probe=_require_symbol(linker_map, READY_PROBE_SYMBOL),
        operator_new=_require_symbol(linker_map, OPERATOR_NEW_SYMBOL),
        population_vtable=_require_symbol(linker_map, POPULATION_VTABLE_SYMBOL),
        city_vtable=_require_symbol(linker_map, CITY_VTABLE_SYMBOL),
        labor_pool_vtable=_require_symbol(linker_map, LABOR_POOL_VTABLE_SYMBOL),
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
    session.interrupt_and_capture("population-eating-timeout")
    raise RuntimeError("timed out waiting for injected call to return")


def _invoke_cdecl(session: GdbSession, address: int, arguments: tuple[int, ...]) -> int:
    stack = int(session.evaluate("$esp"), 0)
    return_address = int(session.evaluate("$eip"), 0)
    call_stack = stack - 4 * (len(arguments) + 1)
    return_breakpoint = session.set_breakpoint(return_address)
    try:
        session.assign(f"*(unsigned int*)0x{call_stack:08x}", return_address)
        for index, argument in enumerate(arguments):
            session.assign(
                f"*(unsigned int*)0x{call_stack + 4 + index * 4:08x}", argument
            )
        session.assign("$esp", call_stack)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_breakpoint(session, return_breakpoint, 30.0)
        result = int(session.evaluate("$eax"), 0)
        session.assign("$esp", stack)
        return result
    finally:
        session.delete_breakpoint(return_breakpoint)


def _invoke_thiscall(
    session: GdbSession, address: int, receiver: int, arguments: tuple[int, ...] = ()
) -> int:
    stack = int(session.evaluate("$esp"), 0)
    return_address = int(session.evaluate("$eip"), 0)
    call_stack = stack - 4 * (len(arguments) + 1)
    return_breakpoint = session.set_breakpoint(return_address)
    try:
        session.assign(f"*(unsigned int*)0x{call_stack:08x}", return_address)
        for index, argument in enumerate(arguments):
            session.assign(
                f"*(unsigned int*)0x{call_stack + 4 + index * 4:08x}", argument
            )
        session.assign("$esp", call_stack)
        session.assign("$ecx", receiver)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_breakpoint(session, return_breakpoint, 30.0)
        result = int(session.evaluate("$eax"), 0)
        session.assign("$esp", stack)
        return result
    finally:
        session.delete_breakpoint(return_breakpoint)


def _allocate_objects(session: GdbSession, addresses: BinaryAddresses) -> ObjectAddresses:
    def allocate(size: int) -> int:
        result = _invoke_cdecl(session, addresses.operator_new, (size,))
        if result == 0:
            raise RuntimeError(f"operator new returned null for {size} bytes")
        return result

    return ObjectAddresses(
        population=allocate(POPULATION_SIZE),
        city=allocate(CITY_SIZE),
        owner=allocate(GREAT_POWER_SIZE),
        baseline=allocate(LABOR_POOL_SIZE),
        production=allocate(LABOR_POOL_SIZE),
        pending=allocate(LABOR_POOL_SIZE),
        outputs=allocate(4),
    )


def _put_short(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<h", buffer, offset, value)


def _write_memory(session: GdbSession, address: int, data: bytes) -> None:
    for offset in range(0, len(data), 0x20):
        session.write_memory(address + offset, data[offset : offset + 0x20])


def _initialize_fixture(
    session: GdbSession,
    addresses: BinaryAddresses,
    objects: ObjectAddresses,
    fixture: Fixture,
) -> None:
    canned, grain, fruit, fish, livestock = fixture.stocks
    city = bytearray(CITY_LIVESTOCK_OFFSET + 2)
    struct.pack_into("<I", city, 0, addresses.city_vtable)
    struct.pack_into("<I", city, CITY_OWNER_OFFSET, objects.owner)
    _put_short(city, CITY_CANNED_OFFSET, canned)
    _put_short(city, CITY_GRAIN_OFFSET, grain)
    _put_short(city, CITY_FRUIT_OFFSET, fruit)
    _put_short(city, CITY_FISH_OFFSET, fish)
    _put_short(city, CITY_LIVESTOCK_OFFSET, livestock)

    owner_targets = bytearray(8)
    for resource, value in zip((0x11, 0x12, 0x13, 0x14), (grain, fruit, fish, livestock)):
        _put_short(owner_targets, (resource - 0x11) * 2, value)

    population = bytearray(POPULATION_SIZE)
    struct.pack_into("<I", population, 0, addresses.population_vtable)
    struct.pack_into("<I", population, 4, objects.city)
    _put_short(population, 8, fixture.population)
    struct.pack_into("<f", population, 0x0C, float(fixture.population))
    struct.pack_into("<III", population, 0x10, objects.baseline, objects.production, objects.pending)

    pool_buffers = []
    for counts in (
        fixture.labor,
        tuple(value + 1 for value in fixture.labor),
        tuple(value & 1 for value in fixture.labor),
    ):
        pool = bytearray(LABOR_POOL_SIZE)
        struct.pack_into("<Ihhh", pool, 0, addresses.labor_pool_vtable, *counts)
        pool_buffers.append(pool)

    _write_memory(session, objects.city, bytes(city[:0x0C]))
    _write_memory(
        session,
        objects.city + CITY_OWNER_OFFSET,
        bytes(city[CITY_OWNER_OFFSET : CITY_OWNER_OFFSET + 4]),
    )
    _write_memory(
        session,
        objects.city + CITY_CANNED_OFFSET,
        bytes(city[CITY_CANNED_OFFSET : CITY_LIVESTOCK_OFFSET + 2]),
    )
    _write_memory(
        session,
        objects.owner + GREAT_POWER_NEED_TARGET_OFFSET + 0x11 * 2,
        bytes(owner_targets),
    )
    _write_memory(session, objects.population, bytes(population))
    _write_memory(session, objects.baseline, bytes(pool_buffers[0]))
    _write_memory(session, objects.production, bytes(pool_buffers[1]))
    _write_memory(session, objects.pending, bytes(pool_buffers[2]))
    _write_memory(session, objects.outputs, bytes(4))
    city_owner = struct.unpack(
        "<I", session.read_memory(objects.city + CITY_OWNER_OFFSET, 4)
    )[0]
    if city_owner != objects.owner:
        raise RuntimeError(
            f"fixture initialization wrote TCity owner 0x{city_owner:08x}, "
            f"expected 0x{objects.owner:08x}"
        )


def _short(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("<h", buffer, offset)[0]


def _pool_counts(buffer: bytes) -> list[int]:
    return [_short(buffer, 4), _short(buffer, 6), _short(buffer, 8)]


def _snapshot(session: GdbSession, objects: ObjectAddresses) -> dict[str, object]:
    city = session.read_memory(objects.city, CITY_SIZE)
    population = session.read_memory(objects.population, POPULATION_SIZE)
    return {
        "food_stocks": {
            "canned": _short(city, CITY_CANNED_OFFSET),
            "grain": _short(city, CITY_GRAIN_OFFSET),
            "fruit": _short(city, CITY_FRUIT_OFFSET),
            "fish": _short(city, CITY_FISH_OFFSET),
            "livestock": _short(city, CITY_LIVESTOCK_OFFSET),
        },
        "substitution_count": _short(city, CITY_SUBSTITUTION_OFFSET),
        "starvation_loss": _short(city, CITY_STARVATION_OFFSET),
        "population_count": _short(population, 8),
        "population_float_bits": struct.unpack_from("<I", population, 0x0C)[0],
        "labor": {
            "baseline": _pool_counts(session.read_memory(objects.baseline, LABOR_POOL_SIZE)),
            "production": _pool_counts(
                session.read_memory(objects.production, LABOR_POOL_SIZE)
            ),
            "pending": _pool_counts(session.read_memory(objects.pending, LABOR_POOL_SIZE)),
        },
    }


def _state_bytes(session: GdbSession, objects: ObjectAddresses) -> bytes:
    return b"".join(
        session.read_memory(address, size)
        for address, size in (
            (objects.population, POPULATION_SIZE),
            (objects.city, 0x0C),
            (objects.city + CITY_OWNER_OFFSET, 4),
            (objects.city + CITY_CANNED_OFFSET, CITY_LIVESTOCK_OFFSET + 2 - CITY_CANNED_OFFSET),
            (objects.owner + GREAT_POWER_NEED_TARGET_OFFSET + 0x11 * 2, 8),
            (objects.baseline, LABOR_POOL_SIZE),
            (objects.production, LABOR_POOL_SIZE),
            (objects.pending, LABOR_POOL_SIZE),
        )
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
        objects = _allocate_objects(session, addresses)
        for address, size in (
            (objects.population, POPULATION_SIZE),
            (objects.city, CITY_SIZE),
            (objects.owner, GREAT_POWER_SIZE),
            (objects.baseline, LABOR_POOL_SIZE),
            (objects.production, LABOR_POOL_SIZE),
            (objects.pending, LABOR_POOL_SIZE),
            (objects.outputs, 4),
        ):
            _write_memory(session, address, bytes(size))

        observations = {}
        for fixture in FIXTURES:
            _initialize_fixture(session, addresses, objects, fixture)
            before = _state_bytes(session, objects)
            _invoke_thiscall(
                session,
                addresses.pretend,
                objects.population,
                (objects.outputs, objects.outputs + 2),
            )
            outputs = session.read_memory(objects.outputs, 4)
            after = _state_bytes(session, objects)
            pretend = {
                "substitution_count": _short(outputs, 0),
                "starvation_loss": _short(outputs, 2),
                "input_unchanged": after == before,
            }

            _initialize_fixture(session, addresses, objects, fixture)
            _invoke_thiscall(session, addresses.eat, objects.population)
            eat = _snapshot(session, objects)
            observations[fixture.name] = {"pretend": pretend, "eat": eat}

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


def _first_difference(left: object, right: object, path: str = "$") -> dict[str, object] | None:
    if type(left) is not type(right):
        return {"path": path, "retail": left, "recomp": right}
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return {"path": path, "retail": sorted(left), "recomp": sorted(right)}
        for key in left:
            difference = _first_difference(left[key], right[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        for index, (left_value, right_value) in enumerate(zip(left, right, strict=True)):
            difference = _first_difference(left_value, right_value, f"{path}[{index}]")
            if difference is not None:
                return difference
        return None
    if left != right:
        return {"path": path, "retail": left, "recomp": right}
    return None


def _predictor_failure(observation: dict[str, object]) -> dict[str, object] | None:
    pretend = observation["pretend"]
    eat = observation["eat"]
    if not pretend["input_unchanged"]:
        return {"field": "input_unchanged", "value": False}
    for field in ("substitution_count", "starvation_loss"):
        if pretend[field] != eat[field]:
            return {"field": field, "pretend": pretend[field], "eat": eat[field]}
    return None


def _observation_hash(observation: BinaryObservation) -> str:
    payload = json.dumps(observation.fixtures, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def compare_observations(retail: BinaryObservation, recomp: BinaryObservation, run_dir: Path) -> dict[str, object]:
    first_divergence = None
    first_predictor_failure = None
    for fixture in FIXTURES:
        retail_fixture = retail.fixtures[fixture.name]
        recomp_fixture = recomp.fixtures[fixture.name]
        if first_predictor_failure is None:
            for kind, observation in (("retail", retail_fixture), ("recomp", recomp_fixture)):
                failure = _predictor_failure(observation)
                if failure is not None:
                    first_predictor_failure = {"binary": kind, "fixture": fixture.name, **failure}
                    break
        if first_divergence is None:
            difference = _first_difference(retail_fixture, recomp_fixture)
            if difference is not None:
                first_divergence = {"fixture": fixture.name, **difference}

    status = "matched" if first_divergence is None and first_predictor_failure is None else "diverged"
    return {
        "format_version": 1,
        "evidence_kind": "retail_differential",
        "targets": [
            {"original_address": f"0x{RETAIL_EAT:08x}", "name": "TPopulationMgr::Eat"},
            {
                "original_address": f"0x{RETAIL_PRETEND:08x}",
                "name": "TPopulationMgr::PretendToEat",
            },
        ],
        "status": status,
        "fixture_count": len(FIXTURES),
        "coverage": {
            "small_exhaustive_population_range": [0, 4],
            "small_exhaustive_stock_values": [0, 1],
            "small_exhaustive_labor_compositions": True,
            "boundary_population_range": [5, 12],
        },
        "complete_observation_sha256": {
            "retail": _observation_hash(retail),
            "recomp": _observation_hash(recomp),
        },
        "first_divergence": first_divergence,
        "first_predictor_failure": first_predictor_failure,
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

    run_id = f"population-eating-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    run_dir = RESULT_ROOT / run_id
    run_dir.mkdir(parents=True)
    retail = run_binary(
        "retail",
        original,
        BinaryAddresses(
            RETAIL_EAT,
            RETAIL_PRETEND,
            RETAIL_READY_PROBE,
            RETAIL_OPERATOR_NEW,
            RETAIL_POPULATION_VTABLE,
            RETAIL_CITY_VTABLE,
            RETAIL_LABOR_POOL_VTABLE,
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
    (RESULT_ROOT / "population-eating.json").write_text(serialized, encoding="utf-8")
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
