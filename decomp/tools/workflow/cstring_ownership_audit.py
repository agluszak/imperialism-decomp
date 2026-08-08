#!/usr/bin/env python3
"""Audit CString layout boundaries and TObject shallow-clone ownership.

The committed layout snapshot is generated from the semantic class model plus the
real VC5 layout oracle.  Normal gate runs rebuild only the semantic model, verify
that every layout-affecting declaration still has the oracle-backed signature, and
regenerate the report in memory.  A declaration change therefore requires an
explicit oracle refresh; host layout is never treated as physical evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.class_model import RecordInfo, build_record_model, load_record_model
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.check_cstring_usage import iter_named_calls, strip_comments


DEFAULT_MODEL = "build-msvc500/generated/record_model.json"
DEFAULT_LAYOUT = "build-msvc500/generated/layout_oracle.json"
DEFAULT_SNAPSHOT = "config/cstring_layout.csv"
DEFAULT_REVIEW = "config/cstring_clone_review.csv"
DEFAULT_REPORT = "docs/reference/cstring-ownership-audit.md"

CLONE_OWNER_EVIDENCE = {
    "TObject": "raw polymorphic byte copy via 0x004798d0 -> slot 0x24 / 0x00415ce0",
    "TView": "raw copy plus TView fix-up at 0x0048bfd0 / 0x0048bef0",
    "TPicture": "raw copy plus TView/picture fix-up at 0x0048f640",
    "TControl": "clone rejected at 0x00435760",
    "TEventHandler": "base-header-only construction at 0x0048a7c0",
    "TStaticText": "class string fix-up at 0x0048fc00 / 0x0048fb10",
}
REVIEW_STATUSES = {
    "retail_raw_copy_risk",
    "clone_rejected",
    "base_header_clone_only",
    "deep_copy_fixup",
}
RAW_CALLS = {
    "memcpy": (0, 1),
    "memmove": (0, 1),
    "ReadBytes": (0,),
    "WriteBytes": (0,),
}


@dataclass(frozen=True)
class LayoutField:
    record: str
    record_size: int
    field: str
    field_type: str
    storage: str
    offset: int
    size: int
    is_cstring: bool
    semantic_hash: str
    header: str


@dataclass(frozen=True)
class RawSpan:
    path: str
    line: int
    operation: str
    record: str
    start: int
    length: int
    verdict: str
    detail: str


def _normalized_type(type_name: str) -> str:
    value = re.sub(r"\b(?:const|volatile|class|struct)\b", "", type_name)
    value = re.sub(r"\s+", " ", value).strip()
    return value.rstrip(" *&")


def _record_signature(name: str, model: dict[str, RecordInfo], seen: set[str] | None = None) -> str:
    seen = set() if seen is None else set(seen)
    if name in seen or name not in model:
        return name
    seen.add(name)
    record = model[name]
    payload = {
        "name": name,
        "tag": record.tag,
        "bases": [
            {
                "type": base.type,
                "access": base.access,
                "virtual": base.is_virtual,
                "signature": _record_signature(_normalized_type(base.type), model, seen),
            }
            for base in record.bases
        ],
        "fields": [
            {
                "name": field.name,
                "type": field.type,
                "bitfield": field.is_bitfield,
                "array": field.array_count,
            }
            for field in record.fields
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _is_cstring_field(type_name: str) -> bool:
    return re.search(r"\bCString\b", type_name) is not None


def _cstring_storage(type_name: str) -> str:
    if "*" in type_name:
        return "pointer"
    if "[" in type_name:
        return "embedded_array"
    return "embedded"


def _direct_cstring_records(model: dict[str, RecordInfo]) -> set[str]:
    return {
        name
        for name, record in model.items()
        if any(_is_cstring_field(field.type) for field in record.fields)
    }


def _descends_from(name: str, ancestor: str, model: dict[str, RecordInfo]) -> bool:
    pending = [name]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for base in model.get(current, RecordInfo(current, "class", "")).bases:
            base_name = _normalized_type(base.type)
            if base_name == ancestor:
                return True
            pending.append(base_name)
    return False


def _clone_owner(name: str, model: dict[str, RecordInfo]) -> str | None:
    if name in CLONE_OWNER_EVIDENCE:
        return name
    for base in model.get(name, RecordInfo(name, "class", "")).bases:
        owner = _clone_owner(_normalized_type(base.type), model)
        if owner is not None:
            return owner
    return None


def snapshot_rows(model: dict[str, RecordInfo], layout: dict) -> list[LayoutField]:
    rows: list[LayoutField] = []
    layouts = layout.get("layouts", {})
    for name in sorted(_direct_cstring_records(model)):
        record = model[name]
        physical = layouts.get(name)
        if physical is None or physical.get("size") is None:
            raise SystemExit(f"VC5 layout oracle has no record for CString owner {name}")
        signature = _record_signature(name, model)
        for field in record.fields:
            measured = physical.get("fields", {}).get(field.name)
            if measured is None:
                raise SystemExit(f"VC5 layout oracle has no {name}::{field.name} field")
            rows.append(
                LayoutField(
                    record=name,
                    record_size=int(physical["size"]),
                    field=field.name,
                    field_type=field.type,
                    storage=_cstring_storage(field.type) if _is_cstring_field(field.type) else "other",
                    offset=int(measured["offset"]),
                    size=int(measured["size"]),
                    is_cstring=_is_cstring_field(field.type),
                    semantic_hash=signature,
                    header=record.file,
                )
            )
    return rows


def write_snapshot(path: Path, rows: list[LayoutField]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="|", lineterminator="\n")
        writer.writerow(
            [
                "record",
                "record_size",
                "field",
                "field_type",
                "storage",
                "offset",
                "size",
                "is_cstring",
                "semantic_hash",
                "header",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.record,
                    row.record_size,
                    row.field,
                    row.field_type,
                    row.storage,
                    row.offset,
                    row.size,
                    "yes" if row.is_cstring else "no",
                    row.semantic_hash,
                    row.header,
                ]
            )


def load_snapshot(path: Path) -> list[LayoutField]:
    return [
        LayoutField(
            record=row["record"],
            record_size=int(row["record_size"]),
            field=row["field"],
            field_type=row["field_type"],
            storage=row["storage"],
            offset=int(row["offset"]),
            size=int(row["size"]),
            is_cstring=row["is_cstring"] == "yes",
            semantic_hash=row["semantic_hash"],
            header=row["header"],
        )
        for row in read_pipe_rows(path)
    ]


def validate_snapshot(rows: list[LayoutField], model: dict[str, RecordInfo]) -> list[str]:
    errors: list[str] = []
    expected_records = _direct_cstring_records(model)
    actual_records = {row.record for row in rows if row.is_cstring}
    if expected_records != actual_records:
        errors.append(
            "CString owner inventory changed: "
            f"added={sorted(expected_records - actual_records)} "
            f"removed={sorted(actual_records - expected_records)}"
        )
    for name in sorted(expected_records & actual_records):
        expected_hash = _record_signature(name, model)
        hashes = {row.semantic_hash for row in rows if row.record == name}
        if hashes != {expected_hash}:
            errors.append(
                f"{name}: layout-affecting declaration changed; regenerate with the VC5 oracle"
            )
        expected_fields = {field.name for field in model[name].fields}
        actual_fields = {row.field for row in rows if row.record == name}
        if expected_fields != actual_fields:
            errors.append(f"{name}: committed layout field inventory is stale")
    return errors


def _variable_types(text: str, records: set[str]) -> dict[str, str]:
    if not records:
        return {}
    alternatives = "|".join(re.escape(name) for name in sorted(records, key=len, reverse=True))
    pattern = re.compile(
        rf"\b(?P<type>{alternatives})\s*(?:const\s*)?(?:[*&]\s*)?(?P<name>[A-Za-z_]\w*)"
    )
    return {match.group("name"): match.group("type") for match in pattern.finditer(text)}


def _parse_int(expression: str) -> int | None:
    value = expression.strip().lower().rstrip("ul")
    try:
        return int(value, 0)
    except ValueError:
        return None


def _infer_buffer(
    argument: str,
    variables: dict[str, str],
    fields: dict[str, dict[str, LayoutField]],
) -> tuple[str, int] | None:
    expression = argument.strip()
    expression = re.sub(r"^[&*]\s*", "", expression)
    member = re.fullmatch(r"(?P<var>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)", expression)
    if member and member.group("var") in variables:
        record = variables[member.group("var")]
        field = fields.get(record, {}).get(member.group("field"))
        if field is not None:
            return record, field.offset
    if expression in variables:
        return variables[expression], 0
    this_member = re.fullmatch(r"this\s*->\s*(?P<field>[A-Za-z_]\w*)", expression)
    if this_member:
        owners = [
            (record, members[this_member.group("field")].offset)
            for record, members in fields.items()
            if this_member.group("field") in members
        ]
        if len(owners) == 1:
            return owners[0]
    return None


def _infer_length(
    expression: str,
    variables: dict[str, str],
    fields: dict[str, dict[str, LayoutField]],
) -> int | None:
    literal = _parse_int(expression)
    if literal is not None:
        return literal
    match = re.fullmatch(r"sizeof\s*\(\s*(.*?)\s*\)", expression.strip(), re.DOTALL)
    if match is None:
        return None
    target = match.group(1).strip()
    if target in fields and fields[target]:
        return next(iter(fields[target].values())).record_size
    inferred = _infer_buffer(target, variables, fields)
    if inferred is None:
        return None
    record, offset = inferred
    for field in fields.get(record, {}).values():
        if field.offset == offset:
            return field.size
    return next(iter(fields[record].values())).record_size if offset == 0 else None


def scan_raw_spans(repo_root: Path, rows: list[LayoutField], model: dict[str, RecordInfo]) -> list[RawSpan]:
    by_record: dict[str, dict[str, LayoutField]] = {}
    for row in rows:
        by_record.setdefault(row.record, {})[row.field] = row
    records = set(by_record)
    spans: set[RawSpan] = set()
    for path in sorted((repo_root / "src" / "game").rglob("*.cpp")):
        source = path.read_text(encoding="utf-8", errors="ignore")
        text = strip_comments(source)
        variables = _variable_types(text, records)
        for operation, buffer_indexes in RAW_CALLS.items():
            for offset, arguments in iter_named_calls(text, operation):
                if len(arguments) < 2:
                    continue
                length_expression = arguments[-1]
                length = _infer_length(length_expression, variables, by_record)
                for index in buffer_indexes:
                    if index >= len(arguments) - 1:
                        continue
                    inferred = _infer_buffer(arguments[index], variables, by_record)
                    if inferred is None:
                        continue
                    record, start = inferred
                    cstrings = [field for field in by_record[record].values() if field.is_cstring]
                    if length is None:
                        continue
                    end = start + length
                    crossed = [
                        field
                        for field in cstrings
                        if start < field.offset + field.size and end > field.offset
                    ]
                    if crossed:
                        verdict = "crosses_cstring"
                        detail = ", ".join(field.field for field in crossed)
                    elif start == 0 and cstrings and end == min(field.offset for field in cstrings):
                        verdict = "safe_boundary"
                        detail = f"ends at first CString offset 0x{end:x}"
                    else:
                        continue
                    spans.add(
                        RawSpan(
                            path.relative_to(repo_root).as_posix(),
                            text.count("\n", 0, offset) + 1,
                            operation,
                            record,
                            start,
                            length,
                            verdict,
                            detail,
                        )
                    )

        # A full-record sizeof copy crosses inherited CString state even when the
        # field belongs to a base and is not in this record's direct snapshot.
        for operation in ("memcpy", "memmove"):
            for offset, arguments in iter_named_calls(text, operation):
                if len(arguments) < 3:
                    continue
                for type_name in re.findall(r"sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)", arguments[-1]):
                    if type_name in records or any(
                        _descends_from(type_name, owner, model) for owner in records
                    ):
                        spans.add(
                            RawSpan(
                                path.relative_to(repo_root).as_posix(),
                                text.count("\n", 0, offset) + 1,
                                operation,
                                type_name,
                                0,
                                -1,
                                "crosses_cstring",
                                "full-record sizeof copy includes CString state",
                            )
                        )
    return sorted(spans, key=lambda span: (span.path, span.line, span.operation, span.record))


def load_reviews(path: Path) -> dict[str, dict[str, str]]:
    reviews: dict[str, dict[str, str]] = {}
    for row in read_pipe_rows(path):
        name = row.get("class", "").strip()
        if name:
            reviews[name] = row
    return reviews


def validate_reviews(model: dict[str, RecordInfo], reviews: dict[str, dict[str, str]]) -> list[str]:
    owners = sorted(
        name
        for name in _direct_cstring_records(model)
        if _descends_from(name, "TObject", model)
    )
    errors: list[str] = []
    if set(owners) != set(reviews):
        errors.append(
            f"clone review inventory changed: added={sorted(set(owners) - set(reviews))} "
            f"removed={sorted(set(reviews) - set(owners))}"
        )
    for name in sorted(set(owners) & set(reviews)):
        actual_owner = _clone_owner(name, model)
        row = reviews[name]
        if row.get("clone_owner") != actual_owner:
            errors.append(
                f"{name}: reviewed clone owner {row.get('clone_owner')} != {actual_owner}"
            )
        if row.get("status") not in REVIEW_STATUSES:
            errors.append(f"{name}: unsupported review status {row.get('status')!r}")
        if not row.get("evidence") or not row.get("note"):
            errors.append(f"{name}: review needs binary evidence and a note")
    return errors


def render_report(
    rows: list[LayoutField],
    model: dict[str, RecordInfo],
    reviews: dict[str, dict[str, str]],
    raw_spans: list[RawSpan],
) -> str:
    cstring_rows = [row for row in rows if row.is_cstring]
    owners = sorted({row.record for row in cstring_rows})
    clone_owners = [name for name in owners if _descends_from(name, "TObject", model)]
    crossings = [span for span in raw_spans if span.verdict == "crosses_cstring"]
    boundaries = [span for span in raw_spans if span.verdict == "safe_boundary"]
    lines = [
        "<!-- AUTO-GENERATED by tools/workflow/cstring_ownership_audit.py; do not hand-edit. -->",
        "# CString ownership and raw-span audit",
        "",
        "Physical offsets come from the real MSVC500 layout oracle. Clone ownership comes",
        "from the source inheritance graph and the listed Windows clone bodies. This report",
        "does not treat MFC internals as game source and does not implement CString itself.",
        "",
        f"- Direct CString-bearing records: {len(owners)}",
        f"- TObject-derived records reviewed for clone behavior: {len(clone_owners)}",
        f"- Proven safe raw CString boundaries: {len(boundaries)}",
        f"- Unreviewed raw spans crossing CString state: {len(crossings)}",
        "",
        "## Clone ownership review",
        "",
        "| Class | CString fields (VC5 offsets) | Clone owner | Status | Binary evidence and review |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name in clone_owners:
        fields = ", ".join(
            f"`{row.field}@0x{row.offset:x} ({row.storage})`"
            for row in cstring_rows
            if row.record == name
        )
        review = reviews[name]
        owner = review["clone_owner"]
        note = review["note"]
        evidence = review["evidence"]
        lines.append(
            f"| `{name}` | {fields} | `{owner}` | `{review['status']}` | "
            f"{evidence}: {note} |"
        )
    lines += [
        "",
        "The `retail_raw_copy_risk` rows are reviewed retail behavior, not proof of a",
        "currently exercised failure. They remain visible because copying a live CString",
        "pointer without incrementing its reference count is unsafe if that clone path runs.",
        "",
        "## Raw byte spans",
        "",
        "| Source | Operation | Record span | Verdict | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines.append(
        "| `src/game/app/TObject.cpp:18` | `memcpy` | runtime class `[0, m_nObjectSize)` | "
        "`reviewed_retail_polymorphic_copy` | Listing 0x00415ce0 uses runtime size then "
        "`REP MOVSD/MOVSB`; the source is explicitly quarantined. |"
    )
    for span in raw_spans:
        length = "full record" if span.length < 0 else f"0x{span.start:x}..0x{span.start + span.length:x}"
        lines.append(
            f"| `{span.path}:{span.line}` | `{span.operation}` | `{span.record}` {length} | "
            f"`{span.verdict}` | {span.detail} |"
        )
    lines += [
        "",
        "A `crosses_cstring` row is a hard failure. The report intentionally permits the",
        "two `Province` spans ending exactly at `cityNameA4`; that CString is serialized",
        "separately by the immediately following typed stream call.",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--layout", default=DEFAULT_LAYOUT)
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    parser.add_argument("--review", default=DEFAULT_REVIEW)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument("--clang", default="clang++")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    snapshot_path = resolve_repo_path(repo_root, args.snapshot)
    review_path = resolve_repo_path(repo_root, args.review)
    report_path = resolve_repo_path(repo_root, args.report)

    if args.write:
        model = load_record_model(resolve_repo_path(repo_root, args.model))
        layout = json.loads(resolve_repo_path(repo_root, args.layout).read_text(encoding="utf-8"))
        rows = snapshot_rows(model, layout)
        write_snapshot(snapshot_path, rows)
    else:
        model = build_record_model(repo_root, clang=args.clang)
        rows = load_snapshot(snapshot_path)

    reviews = load_reviews(review_path)
    errors = validate_snapshot(rows, model)
    errors.extend(validate_reviews(model, reviews))
    raw_spans = scan_raw_spans(repo_root, rows, model)
    for span in raw_spans:
        if span.verdict == "crosses_cstring":
            errors.append(
                f"{span.path}:{span.line}: {span.operation} crosses {span.record} CString state: "
                f"{span.detail}"
            )
    report = render_report(rows, model, reviews, raw_spans)
    if args.write:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        print(
            f"Wrote CString audit: {len(_direct_cstring_records(model))} records, "
            f"{len(reviews)} clone reviews -> {report_path.relative_to(repo_root)}"
        )
    elif not report_path.is_file() or report_path.read_text(encoding="utf-8") != report:
        errors.append(f"{report_path.relative_to(repo_root)} is stale; run `just cstring-ownership-audit`")

    if errors:
        print("CString ownership audit FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("CString ownership audit passed: VC5 layouts current and no raw span crosses CString.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
