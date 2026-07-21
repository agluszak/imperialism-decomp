#!/usr/bin/env python3
"""Differentially analyze retained Mac View widget payload bytes by class.

The report correlates serialized byte ranges with already-decoded semantic
fields.  It is Mac resource-format evidence only and never asserts Windows ABI
layout, inheritance, addresses, or calling conventions.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.ui_codegen import IR_PATH, load_ui_views
from tools.workflow.mac_control_usage import TYPE_FAMILY_CLASSES, build_index


FORMAT_VERSION = 1
REPORT_PATH = "docs/reference/mac_payload_diff.json"
SEGMENTS = (
    "common_flags",
    "drawing_environment",
    "window_prefix",
    "family_payload",
)


def _flatten_scalars(prefix: str, value: object, output: dict[str, int]) -> None:
    if isinstance(value, bool):
        output[prefix] = int(value)
    elif isinstance(value, int):
        output[prefix] = value
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _flatten_scalars(f"{prefix}[{index}]", item, output)
    elif isinstance(value, dict):
        for key, item in sorted(value.items()):
            if key in {
                "offset",
                "size",
                "raw_hex",
                "cluster_attributes_hex",
                "edit_attributes_hex",
                "number_attributes_hex",
                "number_tail_hex",
                "text_attributes_hex",
                "text_tail_hex",
                "text_view_attributes_hex",
                "text_view_tail_hex",
            }:
                continue
            child = f"{prefix}.{key}" if prefix else key
            _flatten_scalars(child, item, output)


def _semantics(node: dict) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in (
        "tag_value",
        "state",
        "enabled",
        "input_gate",
        "child_hit_test",
        "control_value",
    ):
        _flatten_scalars(key, node.get(key), result)
    _flatten_scalars("geometry", node.get("geometry", {}), result)
    _flatten_scalars("family", node.get("family", {}), result)
    return result


def _segments(node: dict) -> dict[str, bytes]:
    family = node.get("family", {})
    return {
        "common_flags": bytes.fromhex(str(node.get("common_flags_hex", ""))),
        "drawing_environment": bytes.fromhex(str(node.get("drawing_environment_hex", ""))),
        "window_prefix": bytes.fromhex(str(node.get("window_prefix_hex", ""))),
        "family_payload": bytes.fromhex(str(family.get("raw_hex", ""))),
    }


def load_records(repo_root: Path) -> list[dict]:
    control_index = build_index(repo_root)
    control_nodes = {
        (str(node["screen"]), int(node["offset"])): node
        for node in control_index["nodes"]
    }
    records: list[dict] = []
    for key, view in sorted(load_ui_views(repo_root).items(), key=lambda item: item[0].text()):
        for node in sorted(view.get("nodes", []), key=lambda item: int(item["offset"])):
            offset = int(node["offset"])
            control = control_nodes[(key.text(), offset)]
            records.append(
                {
                    "id": f"{key.resource_file}:View:{key.view_id}@0x{offset:04x}",
                    "screen": f"{key.resource_file}:View:{key.view_id}",
                    "class": str(control["class"]),
                    "class_source": str(control["class_source"]),
                    "type_code": str(node.get("type_code", "")),
                    "segments": _segments(node),
                    "semantics": _semantics(node),
                }
            )
    return records


def _ranges(offsets: list[int]) -> list[tuple[int, int]]:
    if not offsets:
        return []
    result: list[tuple[int, int]] = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset != previous + 1:
            result.append((start, previous + 1))
            start = offset
        previous = offset
    result.append((start, previous + 1))
    return result


def _encode(value: int, width: int) -> bytes | None:
    signed = value < 0
    minimum = -(1 << (width * 8 - 1)) if signed else 0
    maximum = (1 << (width * 8 - (1 if signed else 0))) - 1
    if not minimum <= value <= maximum:
        return None
    return value.to_bytes(width, "big", signed=signed)


def _confidence(width: int, distinct_values: int) -> str:
    if width >= 2 and distinct_values >= 4:
        return "high"
    if width >= 2 and distinct_values >= 3:
        return "medium"
    return "low"


def _analyze_partition(records: list[dict], segment: str, length: int) -> dict:
    payloads = [record["segments"][segment] for record in records]
    invariant_offsets = [
        offset for offset in range(length) if len({payload[offset] for payload in payloads}) == 1
    ]
    varying_offsets = sorted(set(range(length)) - set(invariant_offsets))
    invariant_ranges = [
        {
            "start": start,
            "end": end,
            "hex": payloads[0][start:end].hex(),
        }
        for start, end in _ranges(invariant_offsets)
    ]

    common_fields = set.intersection(*(set(record["semantics"]) for record in records))
    correlations: list[dict] = []
    covered: set[int] = set()
    for field in sorted(common_fields):
        values = [record["semantics"][field] for record in records]
        distinct = len(set(values))
        if distinct < 2:
            continue
        for width in (1, 2, 4):
            encoded = [_encode(value, width) for value in values]
            if any(value is None for value in encoded):
                continue
            for offset in range(0, length - width + 1):
                if all(payloads[index][offset : offset + width] == encoded[index] for index in range(len(records))):
                    confidence = _confidence(width, distinct)
                    correlations.append(
                        {
                            "field": field,
                            "start": offset,
                            "end": offset + width,
                            "width": width,
                            "byte_order": "big",
                            "distinct_values": distinct,
                            "confidence": confidence,
                        }
                    )
                    # Low-confidence matches remain visible as candidates but do
                    # not explain bytes away; two-value and one-byte coincidences
                    # are too collision-prone to close decoder evidence gaps.
                    if confidence != "low":
                        covered.update(range(offset, offset + width))
    correlations.sort(
        key=lambda item: (
            item["start"],
            -item["width"],
            item["field"],
        )
    )
    unexplained_offsets = sorted(set(varying_offsets) - covered)
    unexplained_ranges = []
    for start, end in _ranges(unexplained_offsets):
        observed = sorted({payload[start:end].hex() for payload in payloads})
        unexplained_ranges.append(
            {
                "start": start,
                "end": end,
                "observed_count": len(observed),
                "observed_hex": observed[:8],
                "observed_truncated": len(observed) > 8,
            }
        )
    return {
        "length": length,
        "instance_count": len(records),
        "instances": [record["id"] for record in records],
        "invariant_byte_count": len(invariant_offsets),
        "varying_byte_count": len(varying_offsets),
        "correlated_varying_byte_count": len(set(varying_offsets) & covered),
        "unexplained_varying_byte_count": len(unexplained_offsets),
        "invariant_ranges": invariant_ranges,
        "correlations": correlations,
        "unexplained_varying_ranges": unexplained_ranges,
    }


def _length_delta(
    class_name: str,
    type_code: str,
    segment: str,
    lengths: list[int],
    records_by_class: dict[str, list[dict]],
) -> dict | None:
    reference_class = TYPE_FAMILY_CLASSES.get(type_code)
    if not reference_class or reference_class == class_name:
        return None
    reference_lengths = sorted(
        {
            len(record["segments"][segment])
            for record in records_by_class.get(reference_class, [])
            if record["type_code"] == type_code
        }
    )
    if not reference_lengths or lengths == reference_lengths:
        return None
    class_payloads = [
        record["segments"][segment]
        for record in records_by_class[class_name]
        if record["type_code"] == type_code
    ]
    reference_payloads = [
        record["segments"][segment]
        for record in records_by_class.get(reference_class, [])
        if record["type_code"] == type_code
    ]
    prefix_lengths_by_payload = []
    for payload in class_payloads:
        prefix_lengths_by_payload.append(
            {
                len(reference)
                for reference in reference_payloads
                if len(reference) < len(payload) and payload.startswith(reference)
            }
        )
    shared_prefix_lengths = (
        set.intersection(*prefix_lengths_by_payload) if prefix_lengths_by_payload else set()
    )
    exact_appended_suffixes = []
    for prefix_length in sorted(shared_prefix_lengths):
        suffixes = sorted({payload[prefix_length:].hex() for payload in class_payloads})
        exact_appended_suffixes.append(
            {
                "prefix_length": prefix_length,
                "suffix_lengths": sorted({len(payload) - prefix_length for payload in class_payloads}),
                "distinct_suffixes": len(suffixes),
                "suffix_hex": suffixes[:8],
                "suffixes_truncated": len(suffixes) > 8,
            }
        )
    return {
        "reference_type_family_class": reference_class,
        "reference_lengths": reference_lengths,
        "class_lengths": lengths,
        "exact_appended_suffixes": exact_appended_suffixes,
        "interpretation": (
            "Class-specific serialized shape relative to the generic type-family records; "
            "this is not evidence of Windows inheritance or object layout."
        ),
    }


def build_report(repo_root: Path) -> dict:
    ir_data = json.loads((repo_root / IR_PATH).read_text(encoding="utf-8"))
    records = load_records(repo_root)
    records_by_class: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        records_by_class[record["class"]].append(record)

    classes: dict[str, dict] = {}
    partition_count = 0
    correlation_count = 0
    high_confidence_count = 0
    unexplained_byte_count = 0
    for class_name, class_records in sorted(records_by_class.items()):
        if len(class_records) < 2:
            continue
        type_counts = Counter(record["type_code"] for record in class_records)
        class_entry = {
            "instance_count": len(class_records),
            "class_sources": dict(sorted(Counter(record["class_source"] for record in class_records).items())),
            "type_codes": dict(sorted(type_counts.items())),
            "screens": sorted({record["screen"] for record in class_records}),
            "segments": {},
        }
        for segment in SEGMENTS:
            segment_groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
            for record in class_records:
                segment_groups[(record["type_code"], len(record["segments"][segment]))].append(record)
            partitions = []
            for (type_code, length), partition_records in sorted(segment_groups.items()):
                if len(partition_records) < 2:
                    continue
                partition = _analyze_partition(partition_records, segment, length)
                partition["type_code"] = type_code
                partitions.append(partition)
                partition_count += 1
                correlation_count += len(partition["correlations"])
                high_confidence_count += sum(
                    item["confidence"] == "high" for item in partition["correlations"]
                )
                unexplained_byte_count += partition["unexplained_varying_byte_count"]
            lengths_by_type = {
                type_code: sorted(
                    {
                        len(record["segments"][segment])
                        for record in class_records
                        if record["type_code"] == type_code
                    }
                )
                for type_code in sorted(type_counts)
            }
            deltas = [
                delta
                for type_code, lengths in lengths_by_type.items()
                if (
                    delta := _length_delta(
                        class_name,
                        type_code,
                        segment,
                        lengths,
                        records_by_class,
                    )
                )
                is not None
            ]
            class_entry["segments"][segment] = {
                "lengths_by_type": lengths_by_type,
                "type_family_shape_deltas": deltas,
                "partitions": partitions,
            }
        classes[class_name] = class_entry

    single_instance_classes = sorted(
        class_name for class_name, class_records in records_by_class.items() if len(class_records) == 1
    )
    exact_appended_suffix_patterns = sum(
        len(delta["exact_appended_suffixes"])
        for class_entry in classes.values()
        for segment_entry in class_entry["segments"].values()
        for delta in segment_entry["type_family_shape_deltas"]
    )
    return {
        "format_version": FORMAT_VERSION,
        "source": {
            "path": IR_PATH,
            "resource_set_sha256": ir_data.get("resource_set_sha256", ""),
        },
        "policy": (
            "Correlations describe serialized Mac resource bytes only. They do not establish "
            "Windows ABI layout, inheritance, addresses, vtables, or calling conventions."
        ),
        "method": {
            "segments": list(SEGMENTS),
            "alignment": "same effective class, type code, segment, and byte length",
            "correlation": (
                "exact all-instance match against 1-, 2-, or 4-byte big-endian encodings of "
                "already-decoded scalar fields; varying fields only"
            ),
            "confidence": {
                "high": "width >= 2 and at least four distinct semantic values",
                "medium": "width >= 2 and at least three distinct semantic values",
                "low": "two-value, one-byte, or otherwise collision-prone exact match",
            },
        },
        "summary": {
            "records": len(records),
            "classes": len(records_by_class),
            "classes_with_multiple_instances": len(classes),
            "single_instance_classes": len(single_instance_classes),
            "partitions": partition_count,
            "correlations": correlation_count,
            "high_confidence_correlations": high_confidence_count,
            "exact_appended_suffix_patterns": exact_appended_suffix_patterns,
            "unexplained_varying_bytes_across_partitions": unexplained_byte_count,
        },
        "single_instance_classes": single_instance_classes,
        "classes": classes,
    }


def render_report(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _print_class(report: dict, class_name: str, *, as_json: bool) -> None:
    entry = report["classes"].get(class_name)
    if entry is None:
        if class_name in report["single_instance_classes"]:
            raise SystemExit(f"{class_name} has only one committed instance; no differential report")
        raise SystemExit(f"No multi-instance Mac payload class {class_name!r}")
    if as_json:
        print(json.dumps(entry, indent=2, sort_keys=True, ensure_ascii=False))
        return
    print(f"{class_name}: {entry['instance_count']} instances")
    print(f"  type codes: {entry['type_codes']}")
    for segment in SEGMENTS:
        segment_entry = entry["segments"][segment]
        correlations = sum(len(partition["correlations"]) for partition in segment_entry["partitions"])
        unexplained = sum(
            partition["unexplained_varying_byte_count"] for partition in segment_entry["partitions"]
        )
        print(
            f"  {segment}: lengths={segment_entry['lengths_by_type']}, "
            f"partitions={len(segment_entry['partitions'])}, correlations={correlations}, "
            f"unexplained_varying_bytes={unexplained}"
        )
        for partition in segment_entry["partitions"]:
            for correlation in partition["correlations"]:
                print(
                    f"    +0x{correlation['start']:02x}..0x{correlation['end']:02x} "
                    f"{correlation['field']} ({correlation['confidence']})"
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("class_name", nargs="?")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if sum((args.write, args.check, args.class_name is not None)) != 1:
        parser.error("choose exactly one of CLASS, --write, or --check")
    repo_root = repo_root_from_file(__file__)
    report = build_report(repo_root)
    rendered = render_report(report)
    path = repo_root / REPORT_PATH
    if args.write:
        path.write_text(rendered, encoding="utf-8")
        print(
            f"Wrote {REPORT_PATH}: {report['summary']['classes_with_multiple_instances']} "
            "multi-instance classes"
        )
        return 0
    if args.check:
        current = path.read_text(encoding="utf-8") if path.is_file() else ""
        if current != rendered:
            raise SystemExit(f"{REPORT_PATH} is stale; run just mac-payload-diff-update")
        print(
            "Mac payload diff passed: "
            + ", ".join(f"{key}={value}" for key, value in report["summary"].items())
        )
        return 0
    _print_class(report, args.class_name, as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
