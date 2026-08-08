#!/usr/bin/env python3
"""Print reccmp's structured result plus Imperialism symbol ownership.

Reccmp owns exact / effective / mismatch / inconclusive. This tool only adds
local ownership context and formats the first trusted difference.

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


def _load_report(path: Path | None) -> dict[str, Any]:
    if path is None:
        return run_report()
    return json.loads(path.read_text(encoding="utf-8"))


def _entity_map(report: dict[str, Any]) -> dict[int, dict[str, Any]]:
    entities: dict[int, dict[str, Any]] = {}
    for entity in report.get("entities") or []:
        raw = entity.get("address")
        if not raw:
            continue
        entities[int(raw, 16)] = entity
    return entities


def render_entity(
    entity: dict[str, Any],
    *,
    names: dict[int, str],
    ownership: dict[int, str],
) -> str:
    address = int(entity["address"], 16)
    name = entity.get("name") or names.get(address) or "<unnamed>"
    matching = float(entity.get("matching") or 0.0)
    comparison = entity.get("comparison") or {}
    status = comparison.get("status") or "unknown"
    owner = ownership.get(address, "stub/unowned")
    header = f"0x{address:08X}  {matching * 100:6.2f}%  {name}  [{owner}]"

    if status == "exact":
        return f"{header}\n\nexact match — nothing to triage"
    if status == "effective":
        reasons = [
            REASON_LABELS.get(reason, reason.replace("_", " "))
            for reason in (comparison.get("effective_reasons") or [])
        ]
        body = "\n".join(f"  {reason}" for reason in reasons) or "  (unspecified)"
        return f"{header}\n\neffective match — safe to ignore:\n{body}\nno action needed"

    lines = [header, ""]
    if status == "inconclusive":
        reason = comparison.get("inconclusive_reason") or "unknown"
        lines.append(f"inconclusive: {reason.replace('_', ' ')}")
        location = comparison.get("inconclusive_location")
        if location:
            lines.append(f"  at {location}")
        return "\n".join(lines)

    difference = comparison.get("difference") or {}
    kind = difference.get("kind") or "unknown"
    orig = difference.get("orig") or {}
    recomp = difference.get("recomp") or {}
    semantic = comparison.get("semantic_similarity")
    if semantic is not None:
        lines.append(
            f"mismatch ({kind.replace('_', ' ')}; {float(semantic) * 100:.2f}% semantic)"
        )
    else:
        lines.append(f"mismatch ({kind.replace('_', ' ')})")
    lines.append(
        f"  original @ insn {orig.get('instruction_index')} addr {orig.get('address')}"
    )
    lines.append(
        f"  recomp    @ insn {recomp.get('instruction_index')} addr {recomp.get('address')}"
    )
    orig_facts = orig.get("facts") or {}
    recomp_facts = recomp.get("facts") or {}
    if orig_facts or recomp_facts:
        lines.append(f"  orig facts:   {orig_facts}")
        lines.append(f"  recomp facts: {recomp_facts}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("addrs", nargs="*", help="Original addresses (0x...)")
    parser.add_argument("--file", action="append", default=[], help="Source file(s) to expand")
    parser.add_argument("--report-json", type=Path, help="Use an existing reccmp report")
    args = parser.parse_args(argv)

    addrs: list[int] = []
    for raw in args.addrs:
        addrs.append(int(raw, 16))
    repo = repo_root_from_file(__file__, levels_up=2)
    for path in args.file:
        file_path = Path(path)
        if not file_path.is_absolute():
            file_path = repo / path
        addrs.extend(addrs_from_file(file_path))
    if not addrs:
        parser.error("pass at least one address or --file")

    report = _load_report(args.report_json)
    entities = _entity_map(report)
    names = names_by_address(repo)
    ownership = ownership_by_address(repo)
    missing = [addr for addr in addrs if addr not in entities]
    for addr in missing:
        print(f"0x{addr:08X}  not present in reccmp report", file=sys.stderr)
    blocks = [
        render_entity(entities[addr], names=names, ownership=ownership)
        for addr in addrs
        if addr in entities
    ]
    if blocks:
        print("\n\n".join(blocks))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
