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
import struct
import time

from tools.runtime.checkpoints import (
    CHECKPOINT_DIPLOMACY_PHASE,
    CHECKPOINT_TRADE_PHASE,
    SCHEMAS,
    first_checkpoint_difference,
    normalize_native_combined_map,
    normalize_native_diplomacy_phase,
    normalize_native_trade_phase,
    normalize_retail_combined_map,
    normalize_retail_diplomacy_phase,
    normalize_retail_trade_phase,
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
    drive: str = ""
    result_checkpoint_id: str = ""


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


def _diplomacy_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native diplomacy transition under GDB."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="diplomacy_phase",
        native_test="diplomacy_phase_applies_grant_and_consulate",
        action_id="diplomacy_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="diplomacy_phase",
        result_checkpoint_id=CHECKPOINT_DIPLOMACY_PHASE,
    )


def _trade_phase_scenario(fixture: Path) -> Scenario:
    """Reach the loaded map, then drive the native trade transition under GDB."""
    base = _load_save_to_map_scenario(fixture)
    return Scenario(
        name="trade_phase",
        native_test="trade_phase",
        action_id="trade_phase.run",
        fixture=fixture,
        probes=base.probes,
        terminal_checkpoint=base.terminal_checkpoint,
        timeout_seconds=base.timeout_seconds,
        start_action=base.start_action,
        drive="trade_phase",
        result_checkpoint_id=CHECKPOINT_TRADE_PHASE,
    )


def load_scenario(name: str) -> Scenario:
    fixture_root = Path(os.environ.get("IMPERIALISM_SAVE_FIXTURES", FIXTURE_DIR))
    fixture = fixture_root / "beginning_of_game.imp"
    if not fixture.is_file():
        raise SystemExit(f"missing differential fixture {fixture}")
    if name == "load_save_to_map":
        scenario = _load_save_to_map_scenario(fixture)
    elif name == "diplomacy_phase":
        scenario = _diplomacy_phase_scenario(fixture)
    elif name == "trade_phase":
        scenario = _trade_phase_scenario(fixture)
    else:
        raise SystemExit(f"unknown retail checkpoint differential scenario {name!r}")
    checkpoint_id = scenario.result_checkpoint_id or scenario.terminal_checkpoint.checkpoint_id
    schema = SCHEMAS.get(checkpoint_id)
    if schema is None:
        raise SystemExit(f"unknown differential checkpoint {checkpoint_id}")
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


# --- diplomacy_phase retail drive -------------------------------------------------
# Mirrors NativeDiplomacyCases.cpp RunDiplomacyPhase: seed eligibility, a one-time
# grant, and a build-consulate policy on the active nation, then invoke
# TDiplomacyMgr::ApplyDiplomacyInterNationStatesForTurn plus per-nation
# TGreatPower::ReplyToDiplomacyOffers through inferior calls.

_SIM_MGR = 0x006A20F8
_NATION_STATES = 0x006A4370
_DIPLOMACY_MGR = 0x006A43D0
_TERRAIN_TABLE = 0x006A4310
_SET_GRANT_ENTRY = 0x004DE340
_APPLY_DIPLOMACY_TURN = 0x004F01E0
_REPLY_TO_OFFERS = 0x004DF5F0
_MAJOR_NATION_COUNT = 7
_NATION_SLOT_COUNT = 23
_MINOR_NATION_FIRST_SLOT = 7
_DIPLOMACY_PROPOSAL_BUILD_CONSULATE = 0x133


def _eval_int(session: GdbSession, expression: str) -> int:
    return int(session.evaluate(expression).split(maxsplit=1)[0], 0)


def _wait_for_injected_return(
    session: GdbSession,
    breakpoint_number: str,
    deadline: float,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    while time.monotonic() < deadline:
        stop = session.wait_for_stop(min(1.0, deadline - time.monotonic()))
        if stop is None:
            if session.process.poll() is not None:
                raise RuntimeError("debugged game exited before the injected call returned")
            continue
        if is_terminal_stop(stop):
            raise RuntimeError("debugged game exited before the injected call returned")
        if stop.reason == "breakpoint-hit" and stop.breakpoint_number == breakpoint_number:
            return
        role = breakpoint_roles.get(stop.breakpoint_number or "")
        if role is not None and role[0] == "probe" and role[1] is not None:
            probe = role[1]
            occurrence = occurrences.get(probe.probe_id, 0) + 1
            occurrences[probe.probe_id] = occurrence
            records.append(
                {
                    "type": "checkpoint",
                    "seq": len(records),
                    "probe": probe.probe_id,
                    "occurrence": occurrence,
                    "fields": _capture_fields(session, probe),
                }
            )
            session.continue_inferior()
            continue
        session.capture_stop(
            f"unexpected-injected-{stop.signal_name or stop.reason}", stop
        )
        raise RuntimeError(
            f"debugged game stopped unexpectedly during injected call: "
            f"{stop.signal_name or stop.reason}"
        )
    session.interrupt_and_capture("injected-call-timeout")
    raise RuntimeError("timed out waiting for injected call to return")


def _invoke_thiscall(
    session: GdbSession,
    address: int,
    receiver: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    args: tuple[int, ...] = (),
) -> int:
    stack = _eval_int(session, "$esp")
    return_address = _eval_int(session, "$eip")
    return_breakpoint = session.set_breakpoint(return_address)
    try:
        frame = stack - 4 * (len(args) + 1)
        session.assign(f"*(unsigned int*)0x{frame:08x}", return_address)
        for index, argument in enumerate(args):
            session.assign(
                f"*(int*)0x{frame + 4 + 4 * index:08x}", argument
            )
        session.assign("$esp", frame)
        session.assign("$ecx", receiver)
        session.assign("$eip", address)
        session.continue_inferior()
        _wait_for_injected_return(
            session,
            return_breakpoint,
            time.monotonic() + 30.0,
            records,
            occurrences,
            breakpoint_roles,
        )
        result = _eval_int(session, "$eax")
        session.assign("$esp", stack)
        return result
    finally:
        session.delete_breakpoint(return_breakpoint)


def _nation_pointer(session: GdbSession, slot: int) -> int:
    return _eval_int(
        session, f"*(unsigned int*)0x{_NATION_STATES + 4 * slot:08x}"
    )


def _drive_diplomacy_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
) -> None:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    active_slot = _eval_int(session, f"*(short*)0x{sim_mgr + 0x2E:08x}")
    active_nation = _nation_pointer(session, active_slot)
    diplomacy_mgr = _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")
    if active_nation == 0 or diplomacy_mgr == 0:
        raise RuntimeError("retail loaded player has no diplomacy state")
    if (
        _eval_int(
            session,
            f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * _MINOR_NATION_FIRST_SLOT:08x}",
        )
        == 0
    ):
        raise RuntimeError("retail fixture has no first minor nation")

    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            session.assign(f"*(unsigned char*)0x{nation + 0xA0:08x}", 1)

    grant_target = (active_slot + 1) % _MAJOR_NATION_COUNT
    accepted = _invoke_thiscall(
        session,
        _SET_GRANT_ENTRY,
        active_nation,
        records,
        occurrences,
        breakpoint_roles,
        args=(grant_target, 1000),
    )
    if accepted & 0xFF == 0:
        raise RuntimeError("retail rejected the seeded diplomacy grant")
    session.assign(
        f"*(short*)0x{active_nation + 0xB2 + 2 * _MINOR_NATION_FIRST_SLOT:08x}",
        _DIPLOMACY_PROPOSAL_BUILD_CONSULATE,
    )

    _invoke_thiscall(
        session,
        _APPLY_DIPLOMACY_TURN,
        diplomacy_mgr,
        records,
        occurrences,
        breakpoint_roles,
    )
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _REPLY_TO_OFFERS,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )


# --- trade_phase retail drive ---------------------------------------------------
# Mirrors NativeTradeCases.cpp RunTradePhaseCase / ExecuteDoTradeWithoutPhaseAdvance:
# seed merchant capacity + stocks, run the market pipeline, drain ranked deals with
# the human auto-accept substitution, then fold offer cells without StartNextPhase.

_TRADE_MGR = 0x006A43CC
_TRADE_DEAL_CATEGORY_ORDER = 0x0066D810
_INITIALIZE_DEAL_BOOK = 0x004DD310
_CLEAR_TRADE_OFFERS = 0x004DDF90
_RESET_NATION_METRIC_ROWS = 0x005B7FC0
_RUN_NATION_UPDATE_PASSES = 0x005B97C0
_SET_MINORS_TRADE_BIDS = 0x005B9890
_TALLY_TRADE_BIDS = 0x005B98D0
_CALCULATE_NEW_WORLD_PRICES = 0x005B8AA0
_CALCULATE_DEAL_ORDER = 0x005B8080
_SET_DEAL_RESULTS = 0x005B94D0
# TCountry vtable slots (index * 4).
_VT_GET_AMT_UNSOLD = 0x1C * 4
_VT_GET_MERCHANT_CAPACITY = 0x1D * 4
_VT_STILL_BUYING_ITEM = 0x21 * 4
_VT_REPLY_TO_TRADE_OFFER = 0x22 * 4
# Retail CRT srand (cdecl): seeds the thread-local rand() stream that minor bids
# and AI offer replies consume. Must match the srand() call in RunTradePhaseCase.
_SRAND = 0x005E83E0
_TRADE_CATEGORY_COUNT = 0x11
_TRADE_ROW_STRIDE = 0xA0
_TRADE_ROW_BASE = 4  # categoryRows[0] starts at TTradeMgr + 0x04
_TRADE_RANK_LISTS = 0xAA8


def _invoke_virtual(
    session: GdbSession,
    receiver: int,
    slot_offset: int,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    args: tuple[int, ...] = (),
) -> int:
    vtable = _eval_int(session, f"*(unsigned int*)0x{receiver:08x}")
    address = _eval_int(session, f"*(unsigned int*)0x{vtable + slot_offset:08x}")
    return _invoke_thiscall(
        session, address, receiver, records, occurrences, breakpoint_roles, args
    )


def _s16(session: GdbSession, address: int) -> int:
    value = _eval_int(session, f"*(short*)0x{address:08x}") & 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _deal_entry(session: GdbSession, deal_list: int, ordinal: int) -> int:
    data = _eval_int(session, f"*(unsigned int*)0x{deal_list + 4:08x}")
    if data == 0 or ordinal < 1:
        return 0
    return _eval_int(
        session, f"*(unsigned int*)0x{data + 4 * (ordinal - 1):08x}"
    )


def _deal_list_size(session: GdbSession, deal_list: int) -> int:
    if deal_list == 0:
        return 0
    return _eval_int(session, f"*(int*)0x{deal_list + 8:08x}")


def _drive_trade_phase(
    session: GdbSession,
    records: list[dict],
    occurrences: dict[str, int],
    breakpoint_roles: dict[str, tuple[str, "Probe | None"]],
    stages: "dict[str, object] | None" = None,
) -> None:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    trade_mgr = _eval_int(session, f"*(unsigned int*)0x{_TRADE_MGR:08x}")
    active_slot = _s16(session, sim_mgr + 0x2E)
    active_nation = _nation_pointer(session, active_slot)
    if trade_mgr == 0 or active_nation == 0:
        raise RuntimeError("retail loaded game has no trade market")
    if (
        _eval_int(session, f"*(unsigned int*)0x{active_nation + 0x894:08x}") == 0
        or _eval_int(session, f"*(unsigned char*)0x{active_nation + 0xA0:08x}") == 0
    ):
        raise RuntimeError("retail active nation is not a human great power")

    stock_seed = {0: 8, 1: 8, 2: 12, 3: 10, 4: 10, 5: 4, 6: 6,
                  7: 16, 13: 10, 14: 8, 15: 8, 16: 6}
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            continue
        city = _eval_int(session, f"*(unsigned int*)0x{nation + 0x894:08x}")
        if city == 0:
            continue
        session.write_memory(city + 0x5C, b"\x00" * 28)
        for index, value in ((1, 2), (5, 1), (10, 1)):
            session.assign(f"*(short*)0x{city + 0x5C + 2 * index:08x}", value)
        for index, value in stock_seed.items():
            session.assign(
                f"*(short*)0x{city + 0xB6 + 2 * index:08x}", value
            )
        session.assign(f"*(int*)0x{nation + 0x10:08x}", 20000)

    session.write_memory(active_nation + 0x250, b"\x00" * 46)
    session.write_memory(active_nation + 0x1C6, b"\x00" * 46)
    session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 13:08x}", -1)
    session.assign(f"*(short*)0x{active_nation + 0x250 + 2 * 2:08x}", 5)

    _invoke_thiscall(
        session,
        _SRAND,
        0,
        records,
        occurrences,
        breakpoint_roles,
        args=(0x1234,),
    )

    for slot in range(_MAJOR_NATION_COUNT - 1, -1, -1):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _INITIALIZE_DEAL_BOOK,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )

    stage_names = (
        "reset",
        "nation_updates",
        "minors_bids",
        "tally_bids",
        "new_world_prices",
        "deal_order",
    )
    for stage_name, address in zip(
        stage_names,
        (
            _RESET_NATION_METRIC_ROWS,
            _RUN_NATION_UPDATE_PASSES,
            _SET_MINORS_TRADE_BIDS,
            _TALLY_TRADE_BIDS,
            _CALCULATE_NEW_WORLD_PRICES,
            _CALCULATE_DEAL_ORDER,
        ),
    ):
        _invoke_thiscall(
            session, address, trade_mgr, records, occurrences, breakpoint_roles
        )
        if stages is not None:
            stages[stage_name] = _capture_trade_phase(session)["market_rows"]

    row0 = trade_mgr + _TRADE_ROW_BASE
    session.assign(f"*(short*)0x{row0 + 2:08x}", 1)
    session.assign(f"*(short*)0x{row0:08x}", 0)
    next_index = 0
    while True:
        index = _s16(session, row0)
        dispatch = _s16(session, _TRADE_DEAL_CATEGORY_ORDER + 2 * index)
        deal_list = _eval_int(
            session, f"*(unsigned int*)0x{trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch:08x}"
        )
        if _deal_list_size(session, deal_list) != 0:
            break
        next_index = _s16(session, row0) + 1
        session.assign(f"*(short*)0x{row0:08x}", next_index)
        if next_index >= 0x11:
            break

    while _s16(session, row0) <= 0x10:
        index = _s16(session, row0)
        dispatch = _s16(session, _TRADE_DEAL_CATEGORY_ORDER + 2 * index)
        deal_list = _eval_int(
            session, f"*(unsigned int*)0x{trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch:08x}"
        )
        ordinal = _s16(session, row0 + 2)
        entry = _deal_entry(session, deal_list, ordinal)
        if entry == 0:
            raise RuntimeError("retail ranked deal entry is null")
        entry_raw = session.read_memory(entry, 0x10)
        source_slot = struct.unpack("<h", entry_raw[0:2])[0]
        target_slot = struct.unpack("<h", entry_raw[2:4])[0]
        score = struct.unpack("<i", entry_raw[8:12])[0]
        if stages is not None:
            stages.setdefault("deals", []).append(
                {
                    "index": index,
                    "dispatch": dispatch,
                    "ordinal": ordinal,
                    "source": source_slot,
                    "target": target_slot,
                    "score": score,
                    "list_size": _deal_list_size(session, deal_list),
                }
            )
        target_country = _eval_int(
            session,
            f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * target_slot:08x}",
        )
        transfer = _invoke_virtual(
            session,
            target_country,
            _VT_GET_AMT_UNSOLD,
            records,
            occurrences,
            breakpoint_roles,
            args=(dispatch,),
        )
        transfer = ((transfer & 0xFFFF) - 0x10000) if transfer & 0x8000 else transfer & 0xFFFF
        if target_slot < 7 <= source_slot:
            capacity = _invoke_virtual(
                session,
                target_country,
                _VT_GET_MERCHANT_CAPACITY,
                records,
                occurrences,
                breakpoint_roles,
            )
            capacity = ((capacity & 0xFFFF) - 0x10000) if capacity & 0x8000 else capacity & 0xFFFF
            if capacity < transfer:
                transfer = capacity
        if transfer > 0:
            buyer = _eval_int(
                session,
                f"*(unsigned int*)0x{_TERRAIN_TABLE + 4 * source_slot:08x}",
            )
            buyer_power = (
                _nation_pointer(session, source_slot) if source_slot < 7 else 0
            )
            still_buying = 0
            if (
                buyer_power != 0
                and _eval_int(
                    session, f"*(unsigned char*)0x{buyer_power + 0xA0:08x}"
                )
                != 0
            ):
                still_buying = _invoke_virtual(
                    session,
                    buyer,
                    _VT_STILL_BUYING_ITEM,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(dispatch,),
                )
            if buyer_power != 0 and still_buying & 0xFF != 0:
                _invoke_thiscall(
                    session,
                    _SET_DEAL_RESULTS,
                    trade_mgr,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(source_slot, target_slot, transfer, score, dispatch, 0, 0),
                )
            else:
                _invoke_virtual(
                    session,
                    buyer,
                    _VT_REPLY_TO_TRADE_OFFER,
                    records,
                    occurrences,
                    breakpoint_roles,
                    args=(target_slot, transfer, score, dispatch),
                )
        ordinal += 1
        session.assign(f"*(short*)0x{row0 + 2:08x}", ordinal)
        if ordinal > _deal_list_size(session, deal_list):
            while True:
                index = _s16(session, row0) + 1
                session.assign(f"*(short*)0x{row0:08x}", index)
                if index > 0x10:
                    break
                dispatch = _s16(session, _TRADE_DEAL_CATEGORY_ORDER + 2 * index)
                deal_list = _eval_int(
                    session,
                    f"*(unsigned int*)0x{trade_mgr + _TRADE_RANK_LISTS + 4 * dispatch:08x}",
                )
                if _deal_list_size(session, deal_list) != 0:
                    break
            session.assign(f"*(short*)0x{row0 + 2:08x}", 1)
            if stages is not None:
                stages[f"drain_to_{index}"] = _capture_trade_phase(session)[
                    "market_rows"
                ]

    if stages is not None:
        stages["drain_end"] = _capture_trade_phase(session)["market_rows"]

    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation != 0:
            _invoke_thiscall(
                session,
                _CLEAR_TRADE_OFFERS,
                nation,
                records,
                occurrences,
                breakpoint_roles,
            )

    if stages is not None:
        stages["clear_done"] = _capture_trade_phase(session)["market_rows"]

    # Fold the turn-history offer cells: 0x11 rows x 0x17 cells, each cell raised
    # to the running maximum seen 23 cells earlier (deliberately reads across the
    # sub-row boundary into the next contiguous row). Indices are absolute shorts
    # from tradeOfferCells[0] of row 0, matching retail's rowCursor walk.
    cells_base = trade_mgr + _TRADE_ROW_BASE + 0x18
    fold_bytes = _TRADE_CATEGORY_COUNT * _TRADE_ROW_STRIDE - 0x18 + 2
    values = list(
        struct.unpack(
            f"<{fold_bytes // 2}h", session.read_memory(cells_base, fold_bytes)
        )
    )
    original = list(values)
    for row in range(0x11):
        for cell in range(0x17):
            current = row * 0x50 + 46 + cell
            if values[current - 0x17] > values[current]:
                values[current] = values[current - 0x17]
    # Assign only changed cells: bulk -data-write-memory-bytes payloads corrupt
    # memory under winedbg's gdb stub (observed zeroed market rows).
    for index in range(46, len(values)):
        if values[index] != original[index]:
            session.assign(
                f"*(short*)0x{cells_base + 2 * index:08x}", values[index]
            )
    if stages is not None:
        stages["fold_done"] = _capture_trade_phase(session)["market_rows"]


def _capture_trade_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    trade_mgr = _eval_int(session, f"*(unsigned int*)0x{_TRADE_MGR:08x}")
    diplomacy_mgr = _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")
    rows = []
    # The maximum-offer sub-row intentionally runs 23 cells past the declared
    # array boundary into the following row (or the trailing padding on row 16).
    rows_region = session.read_memory(
        trade_mgr + _TRADE_ROW_BASE, _TRADE_CATEGORY_COUNT * _TRADE_ROW_STRIDE + 2
    )
    for index in range(17):
        raw = rows_region[index * _TRADE_ROW_STRIDE : (index + 1) * _TRADE_ROW_STRIDE]
        cells = struct.unpack(
            "<69h",
            rows_region[
                index * _TRADE_ROW_STRIDE + 0x18 : index * _TRADE_ROW_STRIDE + 0x18 + 138
            ],
        )
        rows.append(
            {
                "previous_price": struct.unpack("<h", raw[4:6])[0],
                "price": struct.unpack("<h", raw[6:8])[0],
                "base_price": struct.unpack("<h", raw[0x16:0x18])[0],
                "request_count": struct.unpack("<h", raw[8:10])[0],
                "offer_count": struct.unpack("<h", raw[10:12])[0],
                "amount_offered": struct.unpack("<h", raw[0x14:0x16])[0],
                "adjusted_offer_count": struct.unpack("<d", raw[0x0C:0x14])[0],
                "current_offer_by_nation": list(cells[:23]),
                "maximum_offer_by_nation": list(cells[46:69]),
            }
        )
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        arrays = struct.unpack(
            "<115h", session.read_memory(nation + 0x1C6, 230)
        )
        city = _eval_int(session, f"*(unsigned int*)0x{nation + 0x894:08x}")
        city_stocks = (
            list(struct.unpack("<23h", session.read_memory(city + 0xB6, 46)))
            if city != 0
            else None
        )
        nations.append(
            {
                "treasury": _eval_int(session, f"*(int*)0x{nation + 0x10:08x}"),
                "available_merchant": _s16(session, nation + 0xA2),
                "merchant_capacity": _s16(session, nation + 0xA4),
                "transport_capacity": _s16(session, nation + 0xA6),
                "reserved_transport": _s16(session, nation + 0xA8),
                "unfilled_trade_offer_count": _s16(session, nation + 0xB0),
                "item_potentials": list(arrays[0:23]),
                "unfilled_trade_turns": list(arrays[23:46]),
                "transported_items": list(arrays[46:69]),
                "remembered_trade_offers": list(arrays[69:92]),
                "purchased_items": list(
                    struct.unpack("<23h", session.read_memory(nation + 0x198, 46))
                ),
                "city_stocks": city_stocks,
            }
        )
    last_processed = _eval_int(
        session, f"*(signed char*)0x{diplomacy_mgr + 0x78E:08x}"
    )
    if last_processed > 0x7F:
        last_processed -= 0x100
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _s16(session, sim_mgr + 0x2E),
        "economic_turn": _s16(session, sim_mgr + 0x2C),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "last_processed_nation": last_processed,
        "market_rows": rows,
        "trade_nations": nations,
    }


def _read_diplomacy_records(session: GdbSession, queue: int) -> list[dict[str, int]]:
    if queue == 0:
        return []
    size = _eval_int(session, f"*(int*)0x{queue + 8:08x}")
    data = _eval_int(session, f"*(unsigned int*)0x{queue + 4:08x}")
    if size <= 0 or data == 0:
        return []
    entries = struct.unpack(f"<{size}I", session.read_memory(data, 4 * size))
    records: list[dict[str, int]] = []
    for entry in entries:
        code, source = struct.unpack("<2h", session.read_memory(entry, 4))
        records.append({"code": code, "source": source})
    return records


def _capture_diplomacy_phase(session: GdbSession) -> dict[str, object]:
    sim_mgr = _eval_int(session, f"*(unsigned int*)0x{_SIM_MGR:08x}")
    diplomacy_mgr = _eval_int(session, f"*(unsigned int*)0x{_DIPLOMACY_MGR:08x}")
    nations: list[dict[str, object] | None] = []
    for slot in range(_MAJOR_NATION_COUNT):
        nation = _nation_pointer(session, slot)
        if nation == 0:
            nations.append(None)
            continue
        block = session.read_memory(nation + 0xB2, 4 * _NATION_SLOT_COUNT)
        policies = list(struct.unpack(f"<{_NATION_SLOT_COUNT}h", block[: 2 * _NATION_SLOT_COUNT]))
        grants = list(struct.unpack(f"<{_NATION_SLOT_COUNT}h", block[2 * _NATION_SLOT_COUNT :]))
        nations.append(
            {
                "treasury": _eval_int(session, f"*(int*)0x{nation + 0x10:08x}"),
                "policies": policies,
                "grants": grants,
                "proposals": _read_diplomacy_records(
                    session,
                    _eval_int(session, f"*(unsigned int*)0x{nation + 0x84C:08x}"),
                ),
                "turn_events": _read_diplomacy_records(
                    session,
                    _eval_int(session, f"*(unsigned int*)0x{nation + 0x848:08x}"),
                ),
            }
        )
    last_processed = _eval_int(
        session, f"*(signed char*)0x{diplomacy_mgr + 0x78E:08x}"
    )
    if last_processed > 0x7F:
        last_processed -= 0x100
    return {
        "turn_phase": _eval_int(session, f"*(int*)0x{sim_mgr + 4:08x}"),
        "active_nation": _eval_int(session, f"*(short*)0x{sim_mgr + 0x2E:08x}"),
        "economic_turn": _eval_int(session, f"*(short*)0x{sim_mgr + 0x2C:08x}"),
        "turn_flow_status_flags": _eval_int(
            session, f"*(unsigned int*)0x{sim_mgr + 0x3C:08x}"
        ),
        "last_processed_nation": last_processed,
        "diplomacy_nations": nations,
    }


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
                if scenario.drive:
                    if terminal_return_number is not None:
                        session.delete_breakpoint(terminal_return_number)
                    if scenario.drive == "diplomacy_phase":
                        _drive_diplomacy_phase(
                            session, records, occurrences, breakpoint_roles
                        )
                        result_fields = _capture_diplomacy_phase(session)
                        result_probe = CHECKPOINT_DIPLOMACY_PHASE
                    elif scenario.drive == "trade_phase":
                        stages: dict[str, object] = {}
                        result_fields = {
                            "pre": _capture_trade_phase(session),
                            "stages": stages,
                        }
                        _drive_trade_phase(
                            session,
                            records,
                            occurrences,
                            breakpoint_roles,
                            stages,
                        )
                        result_fields.update(_capture_trade_phase(session))
                        result_probe = CHECKPOINT_TRADE_PHASE
                    else:
                        raise RuntimeError(
                            f"unknown scenario drive {scenario.drive!r}"
                        )
                    records.append(
                        {
                            "type": "checkpoint",
                            "seq": len(records),
                            "probe": result_probe,
                            "occurrence": 1,
                            "fields": result_fields,
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
    if scenario.drive in {"diplomacy_phase", "trade_phase"}:
        from tools.runtime.native_oracle import run_native_transition

        native_dir = run_dir / "recomp"
        native_dir.mkdir(parents=True, exist_ok=True)
        if (
            run_native_transition(
                scenario.native_test,
                timeout_seconds=timeout_seconds,
                result_dir=native_dir,
                fixture_dir=scenario.fixture.parent,
            )
            != 0
        ):
            raise RuntimeError(
                f"native transition {scenario.native_test} failed; see {native_dir}"
            )
        native_result = json.loads(
            (native_dir / "result.json").read_text(encoding="utf-8")
        )
        captures_path = native_dir / "captures.json"
        if captures_path.is_file():
            native_result["captures"] = json.loads(
                captures_path.read_text(encoding="utf-8")
            )
        if scenario.drive == "diplomacy_phase":
            recomp_observation = normalize_native_diplomacy_phase(native_result)
        else:
            recomp_observation = normalize_native_trade_phase(native_result)
        recomp_identity = native_result.get("host", {}).get("provenance", {})
    else:
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
        recomp_observation = normalize_native_combined_map(native_outcome.result)
        recomp_identity = native_outcome.result.get("host", {}).get("provenance", {})
    result_checkpoint = scenario.result_checkpoint_id or scenario.terminal_checkpoint.checkpoint_id
    retail_records = [
        record
        for record in original_trace.records
        if record.get("probe") == result_checkpoint
    ]
    if len(retail_records) != 1:
        raise RuntimeError(
            f"retail produced {len(retail_records)} result checkpoint records"
        )
    if result_checkpoint == CHECKPOINT_DIPLOMACY_PHASE:
        retail_observation = normalize_retail_diplomacy_phase(
            retail_records[0]["fields"]
        )
    elif result_checkpoint == CHECKPOINT_TRADE_PHASE:
        retail_observation = normalize_retail_trade_phase(
            retail_records[0]["fields"]
        )
    else:
        retail_observation = normalize_retail_combined_map(retail_records[0]["fields"])
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
        "checkpoint_sequence": [result_checkpoint],
        "observations": {
            "retail": retail_observation,
            "recomp": recomp_observation,
        },
        "first_divergence": divergence,
        "binary_identities": {
            "retail": original_trace.metadata["binary"],
            "recomp": recomp_identity.get("runtime_executable"),
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
