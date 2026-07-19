#!/usr/bin/env python3
"""Summarize a class/function vertical slice from local repo evidence."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path


def normalize_hex(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        return f"0x{int(raw, 16):08x}"
    except ValueError:
        return ""


def class_slug(class_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", class_name).strip("_").lower()
    return cleaned or "class"


def load_symbols(repo_root: Path) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for row in read_pipe_rows(repo_root / "config" / "original_entities.csv"):
        addr = normalize_hex(row.get("address") or "")
        name = (row.get("name") or "").strip()
        if addr and name:
            out.append({**row, "address_norm": addr, "name": name})
    return out


def load_autogen_index(repo_root: Path) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    index = (repo_root / "build-msvc500" / "evidence" / "ghidra-export"
             / "src" / "index.csv")
    if not index.exists():
        return out
    for row in read_pipe_rows(index):
        addr = normalize_hex(row.get("address") or "")
        if addr:
            out.append({**row, "address_norm": addr})
    return out


def load_pipe_csv_if_exists(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    return read_pipe_rows(path)


def load_csv_if_exists(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fd:
        return list(csv.DictReader(fd))


def default_macos_evidence_dir(repo_root: Path) -> Path:
    return (repo_root / "vendor" / "macos_codewarrior" / "evidence").resolve()


def candidate_classes_from_vtable_symbols(vtable_symbol_names: list[str]) -> list[str]:
    out: list[str] = []
    for symbol in vtable_symbol_names:
        if symbol.startswith("g_vtbl") and len(symbol) > len("g_vtbl"):
            out.append(symbol[len("g_vtbl") :])
    return sorted(set(out))


def build_macos_evidence(
    *,
    class_name: str,
    vtable_symbol_names: list[str],
    evidence_dir: Path,
    max_methods: int,
) -> dict[str, object]:
    if not evidence_dir.exists():
        return {
            "available": False,
            "evidence_dir": str(evidence_dir),
            "classes": [],
            "notes": ["Run `just mac-evidence` to generate persistent Mac CodeWarrior evidence."],
        }

    class_rows = load_csv_if_exists(evidence_dir / "classes.csv")
    symbol_rows = load_csv_if_exists(evidence_dir / "symbols.csv")
    class_set = {(row.get("class_name") or "").strip() for row in class_rows}
    candidate_classes = [class_name, *candidate_classes_from_vtable_symbols(vtable_symbol_names)]
    candidate_classes = sorted({cls for cls in candidate_classes if cls and cls in class_set})

    classes: list[dict[str, object]] = []
    for cls in candidate_classes:
        methods = [
            {
                "method": row.get("method", ""),
                "signature": row.get("signature", ""),
                "demangled": row.get("demangled", ""),
                "kind": row.get("kind", ""),
                "source": row.get("source", ""),
                "line": row.get("line", ""),
                "confidence": row.get("confidence", ""),
            }
            for row in symbol_rows
            if (row.get("owner") or "").strip() == cls
        ]
        methods.sort(key=lambda row: (row["method"], row["signature"], row["source"], row["line"]))
        classes.append(
            {
                "class_name": cls,
                "method_count": len(methods),
                "methods": methods[:max_methods],
                "truncated": len(methods) > max_methods,
            }
        )

    return {
        "available": True,
        "evidence_dir": str(evidence_dir),
        "classes": classes,
        "notes": [
            "Mac CodeWarrior evidence can guide names/signatures but cannot directly assign Windows addresses, vtables, calling conventions, or inheritance."
        ],
    }


def find_function_body(source_text: str, address: str) -> str:
    marker = f"// FUNCTION: IMPERIALISM {address.upper().replace('0X', '0x')}"
    pos = source_text.find(marker)
    if pos < 0:
        marker = f"// FUNCTION: IMPERIALISM {address}"
        pos = source_text.lower().find(marker.lower())
    if pos < 0:
        return ""
    next_match = re.search(r"\n// FUNCTION: IMPERIALISM 0x[0-9A-Fa-f]+", source_text[pos + 1 :])
    if next_match is None:
        return source_text[pos:]
    return source_text[pos : pos + 1 + next_match.start()]


def extract_calls(body: str) -> list[str]:
    calls = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(", body))
    ignored = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "static_cast",
        "reinterpret_cast",
    }
    return sorted(call for call in calls if call not in ignored and not call.startswith("TGreatPower::"))


def extract_this_fields(body: str) -> list[str]:
    return sorted(set(re.findall(r"this->([A-Za-z_][A-Za-z0-9_]*)", body)))


def parse_slot_expr(slot_expr: str) -> int | None:
    expr = (slot_expr or "").strip().lower()
    if not expr:
        return None
    match = re.fullmatch(r"(0x[0-9a-f]+|\d+)\s*/\s*(0x[0-9a-f]+|\d+)", expr)
    if match:
        lhs = int(match.group(1), 0)
        rhs = int(match.group(2), 0)
        if rhs == 0:
            return None
        return lhs // rhs
    try:
        return int(expr, 0)
    except ValueError:
        return None


def parse_layout_offsets(source_text: str, class_name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    pattern = re.compile(
        rf"offsetof\({re.escape(class_name)},\s*([A-Za-z_][A-Za-z0-9_]*)\)\s*==\s*(0x[0-9A-Fa-f]+|\d+)"
    )
    for match in pattern.finditer(source_text):
        out[match.group(1)] = normalize_hex(match.group(2))
    return out


def extract_allocation_sizes(body: str) -> list[str]:
    sizes: set[str] = set()
    for match in re.finditer(r"AllocateWithFallbackHandler\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*\)", body):
        sizes.add(normalize_hex(match.group(1)))
    return sorted(sizes, key=lambda value: int(value, 16))


def build_class_candidate(
    *,
    class_name: str,
    address: str,
    anchors: dict[str, str],
    symbols: list[dict[str, str]],
    this_fields: list[str],
    layout_offsets: dict[str, str],
    vcall_wrappers: list[dict[str, str]],
    overrides: list[dict[str, str]],
    allocation_sizes: list[str],
    current_function_name: str,
    body_vtable_symbols: list[str],
) -> dict[str, object]:
    primary_vtable = anchors.get("vtable", "")
    vtable_suffix = primary_vtable[4:] if primary_vtable.startswith("0x00") else primary_vtable[2:]
    vtable_suffix = vtable_suffix.lower().lstrip("0") or "0"

    ctor_candidates: list[dict[str, str]] = []
    for row in overrides:
        note = (row.get("note") or "").strip()
        for raw_addr in re.findall(r"0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,8}", note):
            addr = normalize_hex(raw_addr)
            if addr:
                symbol = next((sym["name"] for sym in symbols if sym["address_norm"] == addr), "")
                ctor_candidates.append(
                    {
                        "address": addr,
                        "name": symbol,
                        "confidence": "high",
                        "evidence": f"curated.vtable_annotation:{note}",
                    }
                )
    for row in symbols:
        name = row["name"]
        lower = name.lower()
        if vtable_suffix and vtable_suffix in lower and row.get("type") == "function":
            if "construct" in lower or "ctor" in lower:
                ctor_candidates.append(
                    {
                        "address": row["address_norm"],
                        "name": name,
                        "confidence": "medium",
                        "evidence": "symbol_name_mentions_vtable",
                    }
                )
    if primary_vtable and body_vtable_symbols:
        ctor_candidates.append(
            {
                "address": address,
                "name": current_function_name,
                "confidence": "medium",
                "evidence": "manual_source:vptr_write_in_sliced_function",
            }
        )
    rank = {"low": 1, "medium": 2, "high": 3}
    ctor_dedup: dict[tuple[str, str], dict[str, str]] = {}
    for row in ctor_candidates:
        key = (row["address"], row["name"])
        prev = ctor_dedup.get(key)
        if prev is None or rank.get(row["confidence"], 0) > rank.get(prev["confidence"], 0):
            ctor_dedup[key] = row

    dtor_candidates = [
        {
            "address": row["address_norm"],
            "name": row["name"],
            "confidence": "medium",
            "evidence": "class_method_name_lifetime_pattern",
        }
        for row in symbols
        if row["name"].startswith(f"{class_name}::")
        and any(token in row["name"].lower() for token in ["destruct", "delete", "releaseself"])
    ]

    field_accesses = [
        {
            "offset": layout_offsets.get(field, ""),
            "field": field,
            "size": "",
            "access": "read",
            "function": address,
            "evidence": "manual_source:this_field_access",
        }
        for field in this_fields
    ]

    vtable_slots: list[dict[str, object]] = []
    virtual_callsites: list[dict[str, object]] = []
    for row in vcall_wrappers:
        slot_index = parse_slot_expr(row.get("slot_expr") or "")
        slot_record = {
            "slot": slot_index,
            "slot_expr": row.get("slot_expr", ""),
            "function_addr": "",
            "wrapper": row.get("wrapper_name", ""),
            "thunk": False,
            "destructor_kind": "",
            "confidence": row.get("confidence", ""),
            "evidence": row.get("notes", ""),
        }
        vtable_slots.append(slot_record)
        virtual_callsites.append(
            {
                "function": address,
                "this_offset": 0,
                "slot_index": slot_index,
                "wrapper": row.get("wrapper_name", ""),
                "evidence": "manual_source:generated_vcall_wrapper",
            }
        )

    return {
        "name": class_name,
        "name_source": "symbol",
        "abi": "msvc",
        "typeinfo_addr": "",
        "primary_vtable_addr": primary_vtable,
        "secondary_vtables": [],
        "vtable_slots": vtable_slots,
        "vptr_writes": [
            {
                "function": address,
                "vtable_addr": primary_vtable,
                "symbols": body_vtable_symbols,
                "evidence": "manual_source:vtable_symbol_assignment",
            }
        ]
        if primary_vtable and body_vtable_symbols
        else [],
        "ctor_candidates": sorted(ctor_dedup.values(), key=lambda row: row["address"]),
        "dtor_candidates": sorted(dtor_candidates, key=lambda row: row["address"]),
        "allocation_sizes": allocation_sizes,
        "field_accesses": field_accesses,
        "virtual_callsites": virtual_callsites,
        "base_edges": [],
        "notes": [
            "MSVC model: vfptr points at function pointer array; RTTI COL may be at vfptr[-1] when present.",
            "No inheritance edge is inferred without RTTI, secondary vftable, vptr-write, this-adjustment, or repeated offset evidence.",
        ],
    }


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, summary: dict[str, object]) -> None:
    lines: list[str] = []
    lines.append(f"# Slice Discovery: {summary['class_name']}")
    lines.append("")
    lines.append(f"- Function: `{summary['function_address']}`")
    lines.append(f"- Source: `{summary.get('source_path', '')}`")
    lines.append("")
    lines.append("## Anchors")
    for key, value in (summary.get("anchors") or {}).items():
        lines.append(f"- `{key}`: `{value}`")
    lines.append("")
    lines.append("## Calls In Function")
    for call in summary.get("calls", []):
        lines.append(f"- `{call}`")
    lines.append("")
    lines.append("## this Fields")
    for field in summary.get("this_fields", []):
        lines.append(f"- `{field}`")
    lines.append("")
    lines.append("## Vcall Wrappers")
    for row in summary.get("vcall_wrappers", []):
        assert isinstance(row, dict)
        lines.append(
            f"- `{row.get('wrapper_name', '')}` slot `{row.get('slot_expr', '')}`: "
            f"{row.get('notes', '')}"
        )
    lines.append("")
    lines.append("## ClassCandidate")
    candidate = summary.get("class_candidate") or {}
    assert isinstance(candidate, dict)
    lines.append(f"- `abi`: `{candidate.get('abi', '')}`")
    lines.append(f"- `primary_vtable_addr`: `{candidate.get('primary_vtable_addr', '')}`")
    lines.append(f"- `typeinfo_addr`: `{candidate.get('typeinfo_addr', '')}`")
    lines.append(f"- constructor candidates: `{len(candidate.get('ctor_candidates', []))}`")
    lines.append(f"- destructor candidates: `{len(candidate.get('dtor_candidates', []))}`")
    lines.append(f"- base edges: `{len(candidate.get('base_edges', []))}`")
    lines.append("")
    external = candidate.get("external_evidence") or {}
    if isinstance(external, dict):
        macos = external.get("macos_codewarrior") or {}
        if isinstance(macos, dict) and macos.get("available"):
            lines.append("## Mac CodeWarrior Evidence")
            for cls in macos.get("classes", []):
                if not isinstance(cls, dict):
                    continue
                lines.append(f"- `{cls.get('class_name', '')}` methods: `{cls.get('method_count', 0)}`")
            lines.append("")
    lines.append("## Class Methods")
    for row in summary.get("class_methods", []):
        assert isinstance(row, dict)
        lines.append(f"- `{row.get('address', '')}` `{row.get('name', '')}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("class_name")
    parser.add_argument("--address", required=True, help="Function address to slice.")
    parser.add_argument(
        "--vtable",
        default="",
        help="Primary vftable address to use when the current class name is provisional or wrong.",
    )
    parser.add_argument(
        "--classdesc",
        default="",
        help="Class descriptor/type descriptor address to use when known.",
    )
    parser.add_argument(
        "--name-source",
        default="symbol",
        choices=["rtti", "symbol", "synthetic", "manual"],
        help="Evidence source for the candidate label.",
    )
    parser.add_argument(
        "--source",
        default="src/game/TGreatPower.cpp",
        help="Manual source file to inspect.",
    )
    parser.add_argument(
        "--out-dir",
        default="tmp_decomp/slice_discovery",
        help="Output directory relative to repo root unless absolute.",
    )
    parser.add_argument("--max-methods", type=int, default=80)
    parser.add_argument(
        "--macos-evidence-dir",
        default=str(default_macos_evidence_dir(repo_root)),
        help="Directory containing persistent Mac CodeWarrior evidence generated by `just mac-evidence`.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    class_name = args.class_name
    address = normalize_hex(args.address)
    if not address:
        raise SystemExit(f"Invalid address: {args.address}")
    forced_vtable = normalize_hex(args.vtable)
    forced_classdesc = normalize_hex(args.classdesc)

    symbols = load_symbols(repo_root)
    autogen = load_autogen_index(repo_root)
    vtable_slots = load_pipe_csv_if_exists(repo_root / "config" / "vtable_slots.csv")
    # Duplicate-vtable disambiguation overrides: no override source is currently
    # wired in (the per-class manifest system this used to read was retired).
    overrides: list[dict[str, str]] = []

    anchors: dict[str, str] = {}
    for row in symbols:
        name = row["name"]
        if name == f"g_vtbl{class_name}":
            anchors["vtable"] = row["address_norm"]
        elif name == f"g_pClassDesc{class_name}":
            anchors["classdesc"] = row["address_norm"]
    if forced_vtable:
        anchors["vtable"] = forced_vtable
    if forced_classdesc:
        anchors["classdesc"] = forced_classdesc

    class_methods = [
        {"address": row["address_norm"], "name": row["name"], "size": row.get("size", "")}
        for row in symbols
        if row["name"].startswith(f"{class_name}::")
    ]
    class_methods.sort(key=lambda row: int(row["address"], 16))

    autogen_methods = [
        {
            "address": row["address_norm"],
            "name": row.get("name", ""),
            "file": row.get("file", ""),
        }
        for row in autogen
        if (row.get("name") or "").startswith(f"{class_name}::")
    ]
    autogen_methods.sort(key=lambda row: int(row["address"], 16))
    current_function_name = next(
        (row["name"] for row in symbols if row["address_norm"] == address),
        "",
    )

    source_path = resolve_repo_path(repo_root, args.source)
    macos_evidence_dir = resolve_repo_path(repo_root, args.macos_evidence_dir)
    source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    body = find_function_body(source_text, address)
    calls = extract_calls(body)
    this_fields = extract_this_fields(body)
    layout_offsets = parse_layout_offsets(source_text, class_name)
    allocation_sizes = extract_allocation_sizes(body)
    vtable_symbol_names = sorted(set(re.findall(r"\b(g_vtbl[A-Za-z0-9_]+)", body)))
    if "vtable" not in anchors and vtable_symbol_names:
        for row in symbols:
            if row["name"] == vtable_symbol_names[0]:
                anchors["vtable"] = row["address_norm"]
                break

    call_set = set(calls)
    vcall_wrappers = [
        row
        for row in vtable_slots
        if (row.get("class_name") or class_name) == class_name
        and (row.get("wrapper_name") or "") in call_set
    ]
    vcall_wrappers.sort(key=lambda row: row.get("wrapper_name") or "")

    relevant_overrides = [
        row
        for row in overrides
        if (row.get("class_name") or row.get("class") or "").strip() == class_name
        or (row.get("name") or "").strip() == class_name
    ]
    class_candidate = build_class_candidate(
        class_name=class_name,
        address=address,
        anchors=anchors,
        symbols=symbols,
        this_fields=this_fields,
        layout_offsets=layout_offsets,
        vcall_wrappers=vcall_wrappers,
        overrides=relevant_overrides,
        allocation_sizes=allocation_sizes,
        current_function_name=current_function_name,
        body_vtable_symbols=vtable_symbol_names,
    )
    class_candidate["name_source"] = args.name_source
    class_candidate["external_evidence"] = {
        "macos_codewarrior": build_macos_evidence(
            class_name=class_name,
            vtable_symbol_names=vtable_symbol_names,
            evidence_dir=macos_evidence_dir,
            max_methods=args.max_methods,
        )
    }

    out_dir = resolve_repo_path(repo_root, args.out_dir) / f"{class_slug(class_name)}_{address[2:]}"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(out_dir / "class_methods.csv", ["address", "name", "size"], class_methods)
    write_csv(out_dir / "autogen_methods.csv", ["address", "name", "file"], autogen_methods)
    write_csv(
        out_dir / "calls.csv",
        ["call"],
        [{"call": call} for call in calls],
    )
    write_csv(
        out_dir / "this_fields.csv",
        ["field", "offset"],
        [{"field": field, "offset": layout_offsets.get(field, "")} for field in this_fields],
    )

    summary: dict[str, object] = {
        "class_name": class_name,
        "function_address": address,
        "source_path": str(source_path.relative_to(repo_root)),
        "anchors": anchors,
        "class_methods": class_methods[: args.max_methods],
        "autogen_methods_count": len(autogen_methods),
        "calls": calls,
        "this_fields": this_fields,
        "allocation_sizes": allocation_sizes,
        "vcall_wrappers": vcall_wrappers,
        "vtable_overrides": relevant_overrides,
        "vtable_symbol_names_in_body": vtable_symbol_names,
        "class_candidate": class_candidate,
        "outputs": {
            "class_methods_csv": str(out_dir / "class_methods.csv"),
            "autogen_methods_csv": str(out_dir / "autogen_methods.csv"),
            "calls_csv": str(out_dir / "calls.csv"),
            "this_fields_csv": str(out_dir / "this_fields.csv"),
            "summary_json": str(out_dir / "summary.json"),
            "summary_md": str(out_dir / "summary.md"),
            "class_candidate_json": str(out_dir / "class_candidate.json"),
        },
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "class_candidate.json").write_text(
        json.dumps(class_candidate, indent=2, sort_keys=True), encoding="utf-8"
    )
    write_markdown(out_dir / "summary.md", summary)

    print(f"[saved] {out_dir / 'summary.json'}")
    print(f"[saved] {out_dir / 'summary.md'}")
    print(f"[info] calls={len(calls)} this_fields={len(this_fields)} class_methods={len(class_methods)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
