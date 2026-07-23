#!/usr/bin/env python3
"""Audit function pointers stored in data or taken as addresses in code.

This is the binary-evidence half of the UI gap audit (bd 1uj.58.4).  Normal
source checks consume the committed JSON snapshot; this command is the explicit
Ghidra refresh step.

The scan deliberately reads initialized blocks one byte at a time.  Bulk JPype
``Memory.getBytes`` calls have returned silent all-zero buffers in this project.
Every pointer is resolved through incremental-link thunks before it is joined to
source ownership and reccmp progress.

Known framework containers are retained as classified evidence, not reported as
callback debt: C++ vtables, MFC AFX_MSGMAP entries, and CRuntimeClass
``pfnCreateObject`` slots.  Everything else is a callback/table candidate.

usage:
  data_function_pointers [--all] [--json] [--write]
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file
from tools.source_model import build_model, ownership_view
from tools.ui_codegen import load_recipes


REPORT_PATH = "docs/reference/ui_callback_audit.json"
MESSAGE_MAP_PATH = "docs/reference/message_map_audit.csv"
RTTI_PATH = "config/rtti_class_oracle.csv"
PROGRESS_PATH = "config/baselines/reccmp_progress_baseline.functions.csv"
FORMAT_VERSION = 1
MAX_VTABLE_SLOTS = 512
DATA_LO = 0x00630000
DATA_HI = 0x006B0000
GAME_CODE_HI = 0x005E0000
UI_NAME_TOKENS = (
    "callback",
    "control",
    "dialog",
    "includeview",
    "mci",
    "menu",
    "movie",
    "screen",
    "timer",
    "ui",
    "view",
    "window",
    "wnd",
)


@dataclass(frozen=True)
class FunctionFacts:
    address: int
    name: str
    size: int
    owner: str
    similarity: float | None


def _hex(value: int) -> str:
    return f"0x{value:08x}"


def is_ui_relevant(name: str, registrars: list[str], is_factory: bool) -> bool:
    """Conservative UI relevance classifier used only for report ranking."""
    if is_factory:
        return True
    haystack = " ".join((name, *registrars)).lower()
    return any(token in haystack for token in UI_NAME_TOKENS)


def candidate_rank(row: dict) -> tuple:
    """UI, unowned, zero-call and larger targets sort first."""
    return (
        not bool(row["ui_relevant"]),
        bool(row["owner"]),
        int(row["call_xref_count"]) != 0,
        -int(row["size"]),
        int(row["target"], 16),
    )


def _load_function_facts(repo_root: Path) -> dict[int, FunctionFacts]:
    symbols: dict[int, tuple[str, int]] = {}
    for row in read_pipe_rows(repo_root / "config" / "original_entities.csv"):
        if row.get("type") != "function":
            continue
        try:
            address = int(row["address"], 16)
            size = int(row.get("size") or 0)
        except ValueError:
            continue
        symbols[address] = (row.get("name") or "", size)

    scores: dict[int, float] = {}
    progress_path = repo_root / PROGRESS_PATH
    if progress_path.is_file():
        for row in read_pipe_rows(progress_path):
            try:
                scores[int(row["address"], 16)] = float(row["matching"])
            except (KeyError, TypeError, ValueError):
                continue

    claims = ownership_view(repo_root)
    facts: dict[int, FunctionFacts] = {}
    for address, (name, size) in symbols.items():
        claim = claims.get(address)
        owner = claim.file if claim is not None else ""
        facts[address] = FunctionFacts(address, name, size, owner, scores.get(address))
    return facts


def _load_named_vtables(repo_root: Path) -> dict[int, str]:
    tables: dict[int, str] = {}
    for row in read_pipe_rows(repo_root / "config" / "original_entities.csv"):
        name = row.get("name") or ""
        folded = name.lower()
        if "vftable" not in folded and "vtable" not in folded and "g_vtbl" not in folded:
            continue
        try:
            tables[int(row["address"], 16)] = name
        except ValueError:
            continue
    return tables


def _load_message_map_targets(repo_root: Path) -> tuple[set[int], set[int]]:
    raw: set[int] = set()
    resolved: set[int] = set()
    path = repo_root / MESSAGE_MAP_PATH
    if not path.is_file():
        return raw, resolved
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            try:
                raw.add(int(row["pfn"], 16))
                resolved.add(int(row["handler"], 16))
            except (KeyError, ValueError):
                continue
    return raw, resolved


def _load_rtti_slots(repo_root: Path) -> tuple[set[int], set[int], set[int]]:
    slots: set[int] = set()
    raw: set[int] = set()
    resolved: set[int] = set()
    path = repo_root / RTTI_PATH
    if not path.is_file():
        return slots, raw, resolved
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            try:
                descriptor = int(row["descriptor"], 16)
                thunk = int(row["createobject_thunk"], 16)
                body = int(row["createobject"], 16)
            except (KeyError, ValueError):
                continue
            slots.add(descriptor + 0x0C)
            if thunk:
                raw.add(thunk)
            if body:
                resolved.add(body)
    return slots, raw, resolved


def _validation(report: dict, factory_addresses: set[int]) -> dict:
    targets = {int(row["target"], 16): row for row in report["targets"]}
    movie = targets.get(0x00484230)
    found_factories = sorted(
        address
        for address in factory_addresses
        if address in targets
        and any(
            hit["kind"] == "code_address_take" and hit["classification"] == "candidate"
            for hit in targets[address]["hits"]
        )
    )
    return {
        "movie_notify_handler": {
            "target": "0x00484230",
            "found": movie is not None,
            "classification": (
                sorted({hit["classification"] for hit in movie["hits"]}) if movie else []
            ),
            "note": (
                "Current evidence identifies this as CIncludeView::OnMciNotifyMode in an "
                "AFX_MSGMAP, correcting the issue's older raw-callback hypothesis."
            ),
        },
        "startup_factories": {
            "expected": len(factory_addresses),
            "found": len(found_factories),
            "targets": [_hex(address) for address in found_factories],
        },
    }


def build_report(program, repo_root: Path) -> dict:
    memory = program.getMemory()
    listing = program.getListing()
    functions = program.getFunctionManager()
    references = program.getReferenceManager()
    address_space = program.getAddressFactory().getDefaultAddressSpace()

    facts = _load_function_facts(repo_root)
    model = build_model(repo_root)
    factory_addresses = {recipe.address for recipe in load_recipes(repo_root)}
    message_raw, message_resolved = _load_message_map_targets(repo_root)
    rtti_slots, rtti_raw, rtti_resolved = _load_rtti_slots(repo_root)

    blocks: list[tuple[int, bytes, str]] = []
    executable_ranges: list[tuple[int, int]] = []
    for block in memory.getBlocks():
        start = int(block.getStart().getOffset())
        end = int(block.getEnd().getOffset()) + 1
        if block.isExecute():
            executable_ranges.append((start, end))
        if not block.isInitialized() or block.isExecute() or end <= DATA_LO or start >= DATA_HI:
            continue
        clipped_start = max(start, DATA_LO)
        clipped_end = min(end, DATA_HI)
        data = bytearray(clipped_end - clipped_start)
        base = address_space.getAddress(clipped_start)
        for index in range(len(data)):
            data[index] = memory.getByte(base.add(index)) & 0xFF
        blocks.append((clipped_start, bytes(data), str(block.getName())))

    def in_executable(address: int) -> bool:
        return any(start <= address < end for start, end in executable_ranges)

    def read_bytes(address: int, count: int) -> bytes | None:
        for start, data, _ in blocks:
            offset = address - start
            if 0 <= offset and offset + count <= len(data):
                return data[offset : offset + count]
        return None

    def read_dword(address: int) -> int | None:
        data = read_bytes(address, 4)
        return int.from_bytes(data, "little") if data is not None else None

    resolve_cache: dict[int, int | None] = {}

    def resolve(raw: int) -> int | None:
        if raw in resolve_cache:
            return resolve_cache[raw]
        if not in_executable(raw):
            resolve_cache[raw] = None
            return None
        target = raw
        seen: set[int] = set()
        for _ in range(8):
            if target in seen:
                break
            seen.add(target)
            function = functions.getFunctionAt(address_space.getAddress(target))
            if function is not None and function.isThunk():
                thunked = function.getThunkedFunction(True)
                if thunked is not None:
                    target = int(thunked.getEntryPoint().getOffset())
                    continue
            instruction = listing.getInstructionAt(address_space.getAddress(target))
            if instruction is None:
                # Many ILT entries are intentionally absent from the Ghidra
                # instruction DB.  Read the five-byte E9 rel32 shape directly.
                try:
                    target_address = address_space.getAddress(target)
                    opcode = memory.getByte(target_address) & 0xFF
                    if opcode != 0xE9:
                        break
                    displacement = int.from_bytes(
                        bytes(
                            memory.getByte(target_address.add(1 + index)) & 0xFF
                            for index in range(4)
                        ),
                        "little",
                        signed=True,
                    )
                    target = target + 5 + displacement
                    continue
                except Exception:
                    break
            if instruction.getMnemonicString().lower() != "jmp":
                break
            flows = instruction.getFlows()
            if len(flows) != 1:
                break
            target = int(flows[0].getOffset())
        function = functions.getFunctionAt(address_space.getAddress(target))
        if function is None:
            resolve_cache[raw] = None
            return None
        resolved = int(function.getEntryPoint().getOffset())
        resolve_cache[raw] = resolved
        return resolved

    # Classify addresses occupied by source-annotated vtable slots.  Known next
    # vtable bases are hard boundaries; null tails may be part of an abstract table.
    vtable_slots: dict[int, str] = {}
    known_vtables = _load_named_vtables(repo_root)
    known_vtables.update(model.vtables)
    vtable_starts = sorted(known_vtables)
    vtable_start_set = set(vtable_starts)
    for start in vtable_starts:
        class_name = known_vtables[start]
        for index in range(MAX_VTABLE_SLOTS):
            slot = start + index * 4
            if index and slot in vtable_start_set:
                break
            raw = read_dword(slot)
            if raw is None:
                break
            if raw == 0:
                vtable_slots[slot] = class_name
                continue
            if resolve(raw) is None:
                break
            vtable_slots[slot] = class_name

    callsites: dict[int, set[str]] = defaultdict(set)
    code_takes: list[tuple[int, int, int, str, str]] = []
    instructions = listing.getInstructions(True)
    while instructions.hasNext():
        instruction = instructions.next()
        source_address = int(instruction.getAddress().getOffset())
        source_function = functions.getFunctionContaining(instruction.getAddress())
        source_name = source_function.getName() if source_function is not None else ""
        source_entry = (
            int(source_function.getEntryPoint().getOffset()) if source_function is not None else 0
        )
        for reference in instruction.getReferencesFrom():
            destination = reference.getToAddress()
            if not destination.isMemoryAddress():
                continue
            raw = int(destination.getOffset())
            target = resolve(raw)
            if target is None:
                continue
            reference_type = reference.getReferenceType()
            source_text = f"{source_name} ({_hex(source_entry)})" if source_entry else ""
            if reference_type.isCall():
                callsites[target].add(f"{_hex(source_address)} in {source_text}")
            elif reference_type.isData():
                code_takes.append((source_address, raw, target, source_text, str(instruction)))

    def readers_of(address: int) -> list[str]:
        readers: set[str] = set()
        iterator = references.getReferencesTo(address_space.getAddress(address))
        while iterator.hasNext():
            reference = iterator.next()
            function = functions.getFunctionContaining(reference.getFromAddress())
            if function is None:
                continue
            readers.add(f"{function.getName()} ({function.getEntryPoint()})")
        return sorted(readers)

    def pointer_run(slot: int) -> tuple[int, int, int]:
        start = slot
        end = slot + 4
        while start >= 4:
            raw = read_dword(start - 4)
            if raw is None or (raw != 0 and resolve(raw) is None):
                break
            start -= 4
        while True:
            raw = read_dword(end)
            if raw is None or (raw != 0 and resolve(raw) is None):
                break
            end += 4
        return start, end, (end - start) // 4

    hits_by_target: dict[int, list[dict]] = defaultdict(list)
    seen_hits: set[tuple[str, int, int]] = set()

    for block_start, data, block_name in blocks:
        first = (block_start + 3) & ~3
        last = block_start + len(data) - 4
        for slot in range(first, last + 1, 4):
            raw = read_dword(slot)
            if raw is None:
                continue
            target = resolve(raw)
            if target is None:
                continue
            key = ("data", slot, raw)
            if key in seen_hits:
                continue
            seen_hits.add(key)
            if slot in vtable_slots:
                classification = "vtable"
                container = vtable_slots[slot]
            elif slot in rtti_slots or raw in rtti_raw or target in rtti_resolved:
                classification = "cruntimeclass"
                container = "CRuntimeClass::pfnCreateObject"
            elif raw in message_raw or target in message_resolved:
                classification = "message_map"
                container = "AFX_MSGMAP_ENTRY::pfn"
            else:
                classification = "candidate"
                container = block_name
            run_start, run_end, run_count = pointer_run(slot)
            hits_by_target[target].append(
                {
                    "kind": "data_pointer",
                    "location": _hex(slot),
                    "raw_target": _hex(raw),
                    "classification": classification,
                    "container": container,
                    "pointer_run_start": _hex(run_start),
                    "pointer_run_end": _hex(run_end),
                    "pointer_run_entries": run_count,
                    "readers": sorted(set(readers_of(slot) + readers_of(run_start))),
                }
            )

    for source_address, raw, target, source_text, instruction in code_takes:
        key = ("code", source_address, raw)
        if key in seen_hits:
            continue
        seen_hits.add(key)
        if raw in message_raw or target in message_resolved:
            classification = "message_map"
        elif raw in rtti_raw or target in rtti_resolved:
            classification = "cruntimeclass"
        else:
            classification = "candidate"
        hits_by_target[target].append(
            {
                "kind": "code_address_take",
                "location": _hex(source_address),
                "raw_target": _hex(raw),
                "classification": classification,
                "container": source_text,
                "instruction": instruction,
            }
        )

    rows: list[dict] = []
    for target, hits in sorted(hits_by_target.items()):
        function = functions.getFunctionAt(address_space.getAddress(target))
        fact = facts.get(target)
        name = fact.name if fact and fact.name else (function.getName() if function else "")
        size = fact.size if fact else (int(function.getBody().getNumAddresses()) if function else 0)
        owner = fact.owner if fact else ""
        registrars = sorted(
            {
                hit["container"]
                for hit in hits
                if hit["kind"] == "code_address_take" and hit["container"]
            }
        )
        classifications = sorted({hit["classification"] for hit in hits})
        row = {
            "target": _hex(target),
            "name": name,
            "size": size,
            "owner": owner,
            "similarity": fact.similarity if fact else None,
            "classification": (
                "candidate" if "candidate" in classifications else classifications[0]
            ),
            "ui_relevant": target < GAME_CODE_HI
            and is_ui_relevant(name, registrars, target in factory_addresses),
            "call_xref_count": len(callsites.get(target, set())),
            "callers": sorted(callsites.get(target, set())),
            "registrars": registrars,
            "hits": sorted(hits, key=lambda hit: (hit["kind"], hit["location"])),
        }
        rows.append(row)

    candidates = sorted(
        (row for row in rows if row["classification"] == "candidate"), key=candidate_rank
    )
    counts = Counter(
        hit["classification"] for row in rows for hit in row["hits"]
    )
    report = {
        "format_version": FORMAT_VERSION,
        "generator": "tools/ghidra/data_function_pointers.py",
        "inputs": {
            "binary": "vendor/ghidra/Imperialism",
            "source_model": "src/game + include/game + config/ui_factory_codegen.yml",
            "message_maps": MESSAGE_MAP_PATH,
            "rtti": RTTI_PATH,
            "progress": PROGRESS_PATH,
        },
        "summary": {
            "targets": len(rows),
            "candidates": len(candidates),
            "ui_relevant_candidates": sum(bool(row["ui_relevant"]) for row in candidates),
            "ui_relevant_unowned_candidates": sum(
                bool(row["ui_relevant"] and not row["owner"]) for row in candidates
            ),
            "hits_by_classification": dict(sorted(counts.items())),
        },
        "targets": sorted(rows, key=lambda row: int(row["target"], 16)),
        "ranked_candidates": [row["target"] for row in candidates],
    }
    report["validation"] = _validation(report, factory_addresses)
    validation = report["validation"]
    if not validation["movie_notify_handler"]["found"]:
        raise ValueError("validation target 0x00484230 was not found")
    if validation["startup_factories"]["found"] != validation["startup_factories"]["expected"]:
        raise ValueError(
            "startup factory validation failed: found "
            f"{validation['startup_factories']['found']} of "
            f"{validation['startup_factories']['expected']}"
        )
    # The complete scan is summarized above, but committing thousands of known
    # framework slots would obscure the actual audit queue.  Preserve the ranked
    # UI candidates plus the excluded movie-handler control as the canonical
    # evidence slice.  The explicit Ghidra refresh can always reproduce totals.
    kept_targets = {
        int(row["target"], 16) for row in candidates if row["ui_relevant"]
    }
    kept_targets.add(0x00484230)
    report["targets"] = [
        row for row in report["targets"] if int(row["target"], 16) in kept_targets
    ]
    report["ranked_candidates"] = [
        row["target"] for row in candidates if row["ui_relevant"]
    ]
    return report


def _print_human(report: dict, include_all: bool) -> None:
    summary = report["summary"]
    print(
        "function-pointer audit: "
        f"targets={summary['targets']} candidates={summary['candidates']} "
        f"ui_relevant={summary['ui_relevant_candidates']} "
        f"ui_relevant_unowned={summary['ui_relevant_unowned_candidates']}"
    )
    by_target = {row["target"]: row for row in report["targets"]}
    for address in report["ranked_candidates"]:
        row = by_target[address]
        if not include_all and not row["ui_relevant"]:
            continue
        owner = row["owner"] or "UNOWNED"
        score = "-" if row["similarity"] is None else f"{row['similarity']:.2%}"
        print(
            f"{address} size={row['size']:>4} calls={row['call_xref_count']:>2} "
            f"score={score:>7} {owner} {row['name']}"
        )
        for hit in row["hits"]:
            if hit["classification"] == "candidate":
                print(f"  {hit['kind']} {hit['location']} in {hit['container']}")


def run(program, argv: list[str]) -> int:
    unknown = [arg for arg in argv if arg not in ("--all", "--json", "--write")]
    if unknown:
        print(f"unknown arguments: {' '.join(unknown)}", file=sys.stderr)
        return 2
    repo_root = repo_root_from_file(__file__)
    try:
        report = build_report(program, repo_root)
    except ValueError as exc:
        print(f"function-pointer audit failed: {exc}", file=sys.stderr)
        return 1
    if "--write" in argv:
        path = repo_root / REPORT_PATH
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary = report["summary"]
        print(
            f"Wrote {REPORT_PATH}: candidates={summary['candidates']} "
            f"ui_relevant={summary['ui_relevant_candidates']} "
            f"ui_relevant_unowned={summary['ui_relevant_unowned_candidates']}"
        )
        if "--json" not in argv:
            return 0
    if "--json" in argv:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_human(report, "--all" in argv)
    return 0


def main() -> int:
    from tools.common import ghidra_env

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return run(program, sys.argv[1:])
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
