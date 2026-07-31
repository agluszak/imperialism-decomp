#!/usr/bin/env python3
"""Interpret reccmp's structured semantic diagnosis for source recovery.

Reccmp owns the machine-level proof and the first trusted divergence.  This
tool adds only Imperialism-specific context: class/stack layout guidance,
symbol ownership, PE data ranges, and the most useful repository command.

Usage:
    just triage 0xADDR [0xADDR ...]
    just triage --file src/game/Foo.cpp
    just triage --report-json report.json 0xADDR
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.common.reccmp_report import run_report
from tools.common.repo import repo_root_from_file
from tools.common.symbols import names_by_address, ownership_by_address
from tools.reccmp.compare_batch import addrs_from_file
from tools.reccmp.global_xref_oracle import PeImage
from tools.workflow.prune_ilt_thunks import original_exe_from_user_yml

REASON_LABELS = {
    "register_allocation": "register allocation",
    "frame_slot_layout": "frame-slot layout",
    "callee_save_substitution": "callee-saved register substitution",
    "instruction_reorder": "independent instruction reordering",
    "commutative_order": "commutative operand order",
    "condition_inversion": "equivalent comparison/condition inversion",
    "dead_operation": "dead register-only operation",
    "padding": "alignment padding",
    "load_folding": "memory-load folding into the consuming instruction",
}


def _hex(value: object) -> str:
    return f"0x{value:x}" if isinstance(value, int) else "unknown"


def _side_location(side: dict[str, Any], label: str) -> str:
    if isinstance(side.get("address"), int):
        return f"{label} 0x{side['address']:08x}"
    if isinstance(side.get("instruction_index"), int):
        return f"{label} instruction {side['instruction_index']}"
    return f"{label} location unknown"


def _format_memory(facts: dict[str, Any]) -> str:
    value = facts.get("value")
    if isinstance(value, str) and value:
        return f"[{value}]"
    symbol = facts.get("symbol")
    base = facts.get("base_register")
    index = facts.get("index_register")
    scale = facts.get("scale", 1)
    displacement = facts.get("displacement", 0)
    terms: list[str] = []
    if isinstance(symbol, str) and symbol:
        terms.append(symbol)
    if isinstance(base, str) and base:
        terms.append(base.lower())
    if isinstance(index, str) and index:
        index_term = index.lower()
        if isinstance(scale, int) and scale != 1:
            index_term += f" * {scale}"
        terms.append(index_term)
    expression = " + ".join(terms)
    if isinstance(displacement, int) and displacement:
        magnitude = f"0x{abs(displacement):x}"
        if expression:
            expression += f" {'-' if displacement < 0 else '+'} {magnitude}"
        elif displacement < 0:
            expression = f"-{magnitude}"
        else:
            expression = magnitude
    return f"[{expression or '0x0'}]"


def _target_text(
    side: dict[str, Any],
    symbols: dict[int, str],
    *,
    include_owner: bool,
    ownership: dict[int, str],
) -> str:
    facts = side.get("facts") or {}
    target = facts.get("target")
    name = facts.get("target_name")
    if isinstance(target, int):
        name = symbols.get(target) or name
    pieces = [_hex(target)]
    if isinstance(name, str) and name:
        pieces.append(name)
    if include_owner and isinstance(target, int):
        pieces.append(f"[{ownership.get(target, 'stub/unowned')}]")
    return " ".join(pieces)


def _memory_interpretation(
    address: int, orig: dict[str, Any], recomp: dict[str, Any]
) -> list[str]:
    orig_facts = orig.get("facts") or {}
    recomp_facts = recomp.get("facts") or {}
    orig_base = str(orig_facts.get("base_register") or "").lower()
    recomp_base = str(recomp_facts.get("base_register") or "").lower()
    if orig_base in {"ebp", "esp"} or recomp_base in {"ebp", "esp"}:
        return [
            "stack-frame location differs",
            "investigate local declaration order, alignment, and EH objects",
            f"next: just stackcmp 0x{address:08x}",
        ]
    orig_symbol = orig_facts.get("symbol")
    recomp_symbol = recomp_facts.get("symbol")
    if orig_symbol != recomp_symbol and (orig_symbol or recomp_symbol):
        return [
            "global symbol differs",
            "likely wrong global selection or missing GLOBAL/STRING annotation",
        ]
    if (
        orig_base
        and orig_base == recomp_base
        and orig_facts.get("displacement") != recomp_facts.get("displacement")
    ):
        return [
            "same object base, different member displacement",
            "likely field declaration, class layout, padding, or receiver-model error",
            "inspect receiver construction and ASSERT_SIZE evidence",
        ]
    return ["address/data-flow differs; trace the producing pointer on both sides"]


def _mismatch_lines(
    entity: dict[str, Any],
    difference: dict[str, Any],
    data_ranges,
    symbols: dict[int, str],
    ownership: dict[int, str],
) -> list[str]:
    kind = difference["kind"]
    orig = difference["orig"]
    recomp = difference["recomp"]
    orig_facts = orig.get("facts") or {}
    recomp_facts = recomp.get("facts") or {}
    location = _side_location(orig, "original")
    lines = ["first actionable mismatch:", f"  {kind.replace('_', ' ')} at {location}"]

    interpretation: list[str]
    if kind == "memory_address":
        lines += [
            f"  original:   {_format_memory(orig_facts)}",
            f"  recompiled: {_format_memory(recomp_facts)}",
        ]
        interpretation = _memory_interpretation(
            int(entity["address"], 16), orig, recomp
        )
    elif kind == "call_target":
        lines += [
            "  original:   "
            + _target_text(orig, symbols, include_owner=True, ownership=ownership),
            "  recompiled: "
            + _target_text(recomp, symbols, include_owner=False, ownership=ownership),
        ]
        target = orig_facts.get("target")
        owner = (
            ownership.get(target, "stub/unowned")
            if isinstance(target, int)
            else "unknown"
        )
        interpretation = [
            f"original callee source owner: {owner}",
            "inspect the original callee symbol, pairing, and dispatch/source ownership",
        ]
        if owner == "stub/unowned":
            interpretation.append("the original callee is stubbed or unowned")
    elif kind == "call_argument":
        register = str(orig_facts.get("register") or "unknown").lower()
        lines += [
            f"  register:   {register}",
            f"  original:   {orig_facts.get('value', 'unknown')}",
            f"  recompiled: {recomp_facts.get('value', 'unknown')}",
        ]
        interpretation = (
            [
                "ECX is a checked thiscall/fastcall input; likely receiver mismatch",
                "inspect the object expression and method owner at this callsite",
            ]
            if register == "ecx"
            else [
                f"checked {register.upper()} argument provenance differs",
                "inspect argument construction and calling-convention metadata",
            ]
        )
    elif kind == "symbol_resolution":
        lines += [
            f"  original:   {orig_facts.get('symbol', 'unresolved')}",
            f"  recompiled: {recomp_facts.get('symbol', 'unresolved')}",
        ]
        interpretation = [
            "symbol resolution differs",
            "check original_entities.csv and add the relevant GLOBAL/STRING/FUNCTION annotation",
        ]
    elif kind == "immediate_value":
        orig_value = orig_facts.get("value")
        recomp_value = recomp_facts.get("value")
        lines += [f"  original:   {orig_value}", f"  recompiled: {recomp_value}"]
        in_data = isinstance(orig_value, int) and any(
            low <= orig_value < high for low, high in data_ranges
        )
        interpretation = [
            (
                "the original value lies in a data section; it may be an unresolved address"
                if in_data
                else "scalar constant, enum, flag, or source expression differs"
            )
        ]
        if in_data:
            interpretation.append("check data symbols and GLOBAL/STRING annotations")
    elif kind == "memory_value":
        lines += [
            f"  original:   {orig_facts.get('value', 'unknown')}",
            f"  recompiled: {recomp_facts.get('value', 'unknown')}",
        ]
        interpretation = [
            "the destination agrees, but the stored value does not",
            "trace the source expression and object/field value provenance",
        ]
    elif kind == "branch_condition":
        lines += [
            f"  original:   {orig_facts.get('predicate', 'unknown')}",
            f"  recompiled: {recomp_facts.get('predicate', 'unknown')}",
        ]
        interpretation = [
            "branch predicate differs; inspect comparison operands and source condition"
        ]
    elif kind == "branch_target":
        lines += [
            f"  original target:   instruction {orig_facts.get('target_instruction_index')}",
            f"  recompiled target: instruction {recomp_facts.get('target_instruction_index')}",
        ]
        interpretation = [
            "canonical successor differs; inspect source block/early-return structure"
        ]
    elif kind == "return_value":
        lines += [
            f"  original:   {orig_facts.get('value', 'unknown')}",
            f"  recompiled: {recomp_facts.get('value', 'unknown')}",
        ]
        interpretation = [
            "typed return state differs; inspect the returned expression and declared type"
        ]
    elif kind == "preserved_state":
        lines += [
            f"  original:   {orig_facts.get('value', 'unknown')}",
            f"  recompiled: {recomp_facts.get('value', 'unknown')}",
        ]
        interpretation = [
            "callee-saved register or stack state differs",
            "inspect prologue/epilogue shape, local lifetime, and inline assembly",
        ]
    else:
        interpretation = ["reccmp reported a structured machine-state mismatch"]

    lines += ["", "interpretation:"] + [f"  {item}" for item in interpretation]
    return lines


def render_entity(
    entity: dict[str, Any],
    data_ranges,
    symbols: dict[int, str],
    ownership: dict[int, str],
) -> str:
    """Render one current-schema entity without inspecting its assembly diff."""
    comparison = entity.get("comparison")
    if not isinstance(comparison, dict) or "status" not in comparison:
        raise ValueError("report entity lacks the structured comparison schema")
    address = int(entity["address"], 16)
    matching = float(entity.get("matching", 0.0)) * 100.0
    status = comparison["status"]
    raw = " raw" if status == "effective" else ""
    lines = [f"0x{address:08x}  {matching:6.2f}%{raw}  {entity['name']}", ""]
    if status == "exact":
        lines.append("exact match — nothing to triage")
    elif status == "effective":
        lines.append("safe to ignore:")
        reasons = comparison.get("effective_reasons") or []
        # Unknown reason keys must never crash triage: the verifier's reason
        # vocabulary can grow ahead of this label table (e.g. load_folding).
        lines.extend(f"  {REASON_LABELS.get(reason, reason)}" for reason in reasons)
        lines += ["", "effective: proved semantically harmless — no action needed"]
    elif status == "mismatch":
        difference = comparison.get("difference")
        if not isinstance(difference, dict):
            raise ValueError("mismatch comparison lacks a difference")
        lines.extend(
            _mismatch_lines(entity, difference, data_ranges, symbols, ownership)
        )
    elif status == "inconclusive":
        reason = str(comparison.get("inconclusive_reason") or "analysis_limit")
        location = comparison.get("inconclusive_location")
        location_text = ""
        if isinstance(location, dict):
            location_text = f" at {_side_location(location, 'original')}"
        lines += [
            "reccmp analysis inconclusive:",
            f"  {reason.replace('_', ' ')}{location_text}",
            "",
            "inconclusive: the verifier could not prove either outcome — this is",
            "NOT evidence of a source defect; do not contort source to chase it.",
            "Investigate verifier/metadata/alignment instead.",
        ]
    else:
        raise ValueError(f"unknown comparison status: {status}")
    return "\n".join(lines)


def _load_report(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    data = value.get("data")
    if value.get("format") != 1 or not isinstance(data, list):
        raise ValueError("not a current reccmp JSON report")
    for entity in data:
        if not isinstance(entity, dict) or not isinstance(
            entity.get("comparison"), dict
        ):
            raise ValueError("report does not contain structured comparison results")
    return data


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    parser.add_argument(
        "--report-json", default="", help="reuse a current-schema report"
    )
    parser.add_argument("--original-exe", default="")
    parser.add_argument(
        "--file",
        action="append",
        default=[],
        type=Path,
        help="triage every // FUNCTION marker in the file(s)",
    )
    parser.add_argument("addrs", nargs="*", help="original-binary offsets (hex)")
    args = parser.parse_args()

    wanted = [int(address, 16) for address in args.addrs]
    for source_file in args.file:
        wanted.extend(addrs_from_file(source_file))
    if not wanted:
        print(
            "no addresses given (pass hex offsets and/or --file SRC.cpp)",
            file=sys.stderr,
        )
        return 2

    exe_path = (
        Path(args.original_exe)
        if args.original_exe
        else original_exe_from_user_yml(repo_root)
    )
    data_ranges = PeImage(exe_path.read_bytes()).data_ranges()
    symbols = names_by_address(repo_root)
    ownership = ownership_by_address(repo_root)
    try:
        data = (
            _load_report(Path(args.report_json))
            if args.report_json
            else run_report(
                args.target,
                Path(args.build_dir),
                diet=True,
                orig_addresses=wanted,
            )
        )
    except (ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"triage: {error}", file=sys.stderr)
        return 2
    by_addr = {int(entity["address"], 16): entity for entity in data}

    rc = 0
    rendered: list[str] = []
    for address in wanted:
        entity = by_addr.get(address)
        if entity is None:
            rendered.append(
                f"0x{address:08x}: not in reccmp report (not paired? run `just addr`)"
            )
            rc = 1
            continue
        try:
            rendered.append(render_entity(entity, data_ranges, symbols, ownership))
        except (KeyError, TypeError, ValueError) as error:
            print(f"triage: 0x{address:08x}: {error}", file=sys.stderr)
            rc = 2
    print("\n\n".join(rendered))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
