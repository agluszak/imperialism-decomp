#!/usr/bin/env python3
"""Gate field offset annotations on recovered class layouts.

For classes whose manifest ``curated.layout.status`` is ``recovered``
(config/classes/<Class>.yml), every non-pad data member must carry a resolvable
offset comment and that comment must match the sequential layout walk used by
gen_recovered_fields_from_headers.

``in_progress`` classes only fail when an explicit annotation disagrees with the
walk. Missing annotations are allowed.

Optional header ``// LAYOUT: RECOVERED|IN_PROGRESS`` must agree with the CSV row.

Usage:
  uv run python -m tools.workflow.check_field_layout_annotations
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from tools.common import class_manifest as cm
from tools.common.field_layout_annotations import (
    LayoutRecoveryStatus,
    build_name_offset_hints,
    field_line_index,
    is_pad_field,
    parse_layout_status_comment,
    read_header_lines,
    resolve_field_offset_from_lines,
)
from tools.common.repo import repo_root_from_file
from tools.ghidra.gen_recovered_fields_from_headers import (
    extract_class_rows,
    load_layout_bases,
)
from tools.ghidra.header_preprocess import class_name_of, parse_header_file

REPO = repo_root_from_file(__file__)
MANIFEST_SOURCE = "config/classes/<Class>.yml (curated.layout)"
INCLUDE_GAME = REPO / "include" / "game"


@dataclass(frozen=True)
class ClassLayoutStatus:
    class_name: str
    status: LayoutRecoveryStatus
    header: str
    note: str


def load_layout_status() -> dict[str, ClassLayoutStatus]:
    """Layout recovery status per class, sourced from the manifests' curated.layout."""
    rows: dict[str, ClassLayoutStatus] = {}
    for cls, manifest in cm.load_all_manifests(REPO).items():
        layout = cm.curated_layout(manifest)
        status_s = (layout.get("status") or "").strip().lower()
        header = (layout.get("header") or "").strip()
        if not status_s or not header:
            continue
        if status_s == "recovered":
            status = LayoutRecoveryStatus.RECOVERED
        elif status_s == "in_progress":
            status = LayoutRecoveryStatus.IN_PROGRESS
        else:
            continue
        rows[cls] = ClassLayoutStatus(cls, status, header, (layout.get("note") or "").strip())
    return rows


def layout_offsets_by_name(path: Path, class_name: str, layout_bases) -> dict[str, int]:
    return {row.field_name: row.offset for row in extract_class_rows(path, class_name, layout_bases)}


def check_class(entry: ClassLayoutStatus, layout_bases) -> list[str]:
    path = INCLUDE_GAME / entry.header
    if not path.exists():
        return [f"{entry.class_name}: missing header {entry.header}"]

    lines = read_header_lines(path)
    header_status = parse_layout_status_comment(lines)
    if header_status is not None and header_status != entry.status:
        return [
            f"{entry.header}: // LAYOUT: {header_status.value.upper()} disagrees with "
            f"manifest curated.layout.status ({entry.status.value})"
        ]

    try:
        parsed = parse_header_file(path)
    except Exception as exc:  # noqa: BLE001
        return [f"{entry.class_name}: header preprocess failed: {exc}"]

    field_names: list[str] = []
    for scope in parsed.namespace.classes:
        if class_name_of(scope) != entry.class_name:
            continue
        field_names = [field.name for field in scope.fields if not is_pad_field(field.name)]
        break

    if not field_names:
        return [f"{entry.class_name}: no data members found in {entry.header}"]

    computed = layout_offsets_by_name(path, entry.class_name, layout_bases)
    hints = build_name_offset_hints(lines)
    violations: list[str] = []

    for field_name in field_names:
        line_idx = field_line_index(lines, field_name)
        explicit, source = resolve_field_offset_from_lines(
            lines, field_name, line_idx, name_hints=hints
        )
        walked = computed.get(field_name)

        if entry.status == LayoutRecoveryStatus.RECOVERED and explicit is None:
            line_no = (line_idx + 1) if line_idx is not None else "?"
            violations.append(
                f"{entry.header}:{line_no}: {entry.class_name}::{field_name} missing offset "
                f"annotation (recovered class; see docs/reference/field-layout-annotations.md)"
            )
            continue

        if explicit is None or walked is None:
            continue

        if explicit != walked:
            line_no = (line_idx + 1) if line_idx is not None else "?"
            violations.append(
                f"{entry.header}:{line_no}: {entry.class_name}::{field_name} annotation "
                f"0x{explicit:x} ({source}) != layout walk 0x{walked:x}"
            )

    return violations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate class field offset annotations.")
    parser.add_argument(
        "--class",
        dest="class_name",
        metavar="NAME",
        help="Only check this class (must have curated.layout.status in its manifest).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    statuses = load_layout_status()
    if not statuses:
        print("No curated.layout.status in any manifest; field layout gate passed (nothing to check).")
        return 0

    if args.class_name:
        entry = statuses.get(args.class_name)
        if entry is None:
            print(f"Class {args.class_name!r} has no curated.layout.status in its manifest")
            return 1
        statuses = {args.class_name: entry}

    layout_bases = load_layout_bases()
    violations: list[str] = []
    checked = 0
    for entry in statuses.values():
        checked += 1
        violations.extend(check_class(entry, layout_bases))

    print(f"Checked layout status for {checked} class(es) from {MANIFEST_SOURCE}")

    if not violations:
        print("Field layout annotation gate passed.")
        return 0

    print("Field layout annotation gate failed:")
    for item in sorted(violations):
        print(f"    - {item}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
