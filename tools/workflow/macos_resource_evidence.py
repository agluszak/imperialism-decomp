#!/usr/bin/env python3
"""Generate metadata-only evidence from Imperialism's classic Mac resources.

The retail Mac build stores its UI descriptions in custom ``View`` resources,
not PowerPlant ``PPob`` resources.  This tool reads resource-only MacBinary files
directly, or uses hfsutils to copy them from the HFS side of the retail CD image.
It never writes resource payloads to the repository: only deterministic CSV/JSON
inventories are retained as evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator, Sequence

from tools.common.repo import repo_root_from_file, resolve_repo_path


DEFAULT_SOURCE = os.environ.get("MACOS_IMPERIALISM_DUMP", "")
EVIDENCE_VERSION = 1
UI_TYPES = {
    b"view",
    b"pict",
    b"cntl",
    b"stat",
    b"clus",
    b"tevw",
    b"wind",
    b"fwnd",
    b"edit",
}


class ResourceFormatError(ValueError):
    """Raised when a MacBinary/resource-fork structure is malformed."""


@dataclass(frozen=True)
class ResourceEntry:
    resource_file: str
    type_code: str
    resource_id: int
    name: str
    attributes: int
    data: bytes


@dataclass(frozen=True)
class WidgetRecord:
    resource_file: str
    view_id: int
    view_name: str
    offset: int
    record_end: int
    type_code: str
    class_name: str
    tag: str
    x: int
    y: int
    width: int
    height: int
    parent_offset: int | None
    parent_tag: str
    depth: int


EXPECTED_STARTUP_1500 = [
    ("view", "base", "", 0, 0, 2000, 2000),
    ("pict", "main", "TGameSetupPicture", 0, 0, 640, 480),
    ("cntl", "load", "", 61, 111, 137, 84),
    ("cntl", "rand", "", 14, 209, 138, 171),
    ("cntl", "mult", "", 458, 258, 143, 140),
    ("cntl", "high", "", 448, 113, 164, 78),
    ("cntl", "scen", "", 1, 397, 156, 72),
    ("tevw", "curs", "TInfoBarText", 180, 424, 274, 52),
    ("cntl", "quit", "", 221, 102, 195, 195),
    ("cntl", "pref", "", 540, 399, 100, 73),
]


def _need(data: bytes, offset: int, size: int, context: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ResourceFormatError(
            f"{context}: need 0x{size:x} bytes at 0x{offset:x}, file size 0x{len(data):x}"
        )


def _u16(data: bytes, offset: int, context: str) -> int:
    _need(data, offset, 2, context)
    return struct.unpack_from(">H", data, offset)[0]


def _s16(data: bytes, offset: int, context: str) -> int:
    _need(data, offset, 2, context)
    return struct.unpack_from(">h", data, offset)[0]


def _u32(data: bytes, offset: int, context: str) -> int:
    _need(data, offset, 4, context)
    return struct.unpack_from(">I", data, offset)[0]


def _decode_mac_text(data: bytes) -> str:
    return data.decode("mac_roman", errors="replace")


def extract_macbinary_resource_fork(blob: bytes) -> tuple[str, bytes]:
    """Return the embedded filename and resource fork from a MacBinary II blob."""

    _need(blob, 0, 128, "MacBinary header")
    name_length = blob[1]
    if blob[0] != 0 or not 1 <= name_length <= 63:
        raise ResourceFormatError("not a MacBinary file (invalid filename header)")
    name = _decode_mac_text(blob[2 : 2 + name_length])
    data_length = _u32(blob, 83, "MacBinary data-fork length")
    resource_length = _u32(blob, 87, "MacBinary resource-fork length")
    resource_offset = 128 + ((data_length + 127) // 128) * 128
    _need(blob, resource_offset, resource_length, "MacBinary resource fork")
    if resource_length == 0:
        raise ResourceFormatError(f"{name}: MacBinary file has no resource fork")
    return name, blob[resource_offset : resource_offset + resource_length]


def parse_resource_fork(resource_file: str, fork: bytes) -> list[ResourceEntry]:
    """Parse a classic Resource Manager fork and return all resource entries."""

    _need(fork, 0, 16, f"{resource_file} resource header")
    data_offset, map_offset, data_length, map_length = struct.unpack_from(">IIII", fork, 0)
    _need(fork, data_offset, data_length, f"{resource_file} resource data")
    _need(fork, map_offset, map_length, f"{resource_file} resource map")
    _need(fork, map_offset, 28, f"{resource_file} resource map header")

    type_list = map_offset + _u16(fork, map_offset + 24, "type-list offset")
    name_list = map_offset + _u16(fork, map_offset + 26, "name-list offset")
    _need(fork, type_list, 2, f"{resource_file} type list")
    _need(fork, name_list, 0, f"{resource_file} name list")
    type_count_minus_one = _u16(fork, type_list, "resource type count")
    type_count = 0 if type_count_minus_one == 0xFFFF else type_count_minus_one + 1

    entries: list[ResourceEntry] = []
    for type_index in range(type_count):
        type_entry = type_list + 2 + type_index * 8
        _need(fork, type_entry, 8, f"{resource_file} type entry")
        type_code = _decode_mac_text(fork[type_entry : type_entry + 4])
        count = _u16(fork, type_entry + 4, "resource count") + 1
        references = type_list + _u16(fork, type_entry + 6, "reference-list offset")
        for resource_index in range(count):
            reference = references + resource_index * 12
            _need(fork, reference, 12, f"{resource_file} resource reference")
            resource_id = _s16(fork, reference, "resource id")
            name_offset = _s16(fork, reference + 2, "resource name offset")
            attributes = fork[reference + 4]
            relative_data = int.from_bytes(fork[reference + 5 : reference + 8], "big")
            length_offset = data_offset + relative_data
            payload_length = _u32(fork, length_offset, "resource payload length")
            payload_offset = length_offset + 4
            _need(fork, payload_offset, payload_length, "resource payload")

            name = ""
            if name_offset != -1:
                pascal_offset = name_list + name_offset
                _need(fork, pascal_offset, 1, "resource name length")
                length = fork[pascal_offset]
                _need(fork, pascal_offset + 1, length, "resource name")
                name = _decode_mac_text(fork[pascal_offset + 1 : pascal_offset + 1 + length])
            entries.append(
                ResourceEntry(
                    resource_file=resource_file,
                    type_code=type_code,
                    resource_id=resource_id,
                    name=name,
                    attributes=attributes,
                    data=fork[payload_offset : payload_offset + payload_length],
                )
            )
    return entries


def parse_macbinary_file(path: Path) -> list[ResourceEntry]:
    name, fork = extract_macbinary_resource_fork(path.read_bytes())
    return parse_resource_fork(name, fork)


def _find_retail_iso(source: Path) -> Path | None:
    candidates: list[Path] = []
    if source.is_file() and source.suffix.lower() == ".iso":
        candidates.append(source)
    elif source.is_dir():
        candidates.extend(
            [
                source / "IMPERIALISM01.iso",
                source.parent / "IMPERIALISM01.iso",
            ]
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def _resource_macbinary_files(source: Path) -> list[Path]:
    if source.is_file() and source.suffix.lower() != ".iso":
        return [source]
    if not source.is_dir():
        return []
    files = sorted(source.glob("*.rsrc.bin"))
    if files:
        return files
    return sorted(source.glob("**/*.rsrc.bin"))


def _run_hfsutils(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


@contextmanager
def resource_macbinary_files(source: Path) -> Iterator[list[Path]]:
    """Resolve pre-extracted resource MacBinary files or extract them from HFS."""

    files = _resource_macbinary_files(source)
    if files:
        yield files
        return

    iso = _find_retail_iso(source)
    if iso is None:
        raise FileNotFoundError(
            f"{source}: no *.rsrc.bin files or IMPERIALISM01.iso found; "
            "point --source at the retail directory, HFS ISO, or an extracted MacBinary directory"
        )
    missing = [name for name in ("hmount", "hcopy", "humount") if shutil.which(name) is None]
    if missing:
        raise FileNotFoundError(f"reading {iso} requires hfsutils: missing {', '.join(missing)}")

    with tempfile.TemporaryDirectory(prefix="imperialism-mac-resources-") as temp_dir:
        output_dir = Path(temp_dir)
        mounted = False
        mount = _run_hfsutils(["hmount", str(iso)])
        if mount.returncode != 0:
            raise RuntimeError(f"hmount {iso} failed:\n{mount.stderr or mount.stdout}")
        mounted = True
        try:
            copied = _run_hfsutils(
                ["hcopy", "-m", ":Imperialism:Resources:*", str(output_dir)]
            )
            if copied.returncode != 0:
                raise RuntimeError(
                    f"hcopy from {iso} failed:\n{copied.stderr or copied.stdout}"
                )
            files = sorted(output_dir.glob("*.rsrc.bin"))
            if not files:
                raise RuntimeError(f"hcopy from {iso} produced no *.rsrc.bin files")
            yield files
        finally:
            if mounted:
                _run_hfsutils(["humount"])


def load_resources(source: Path) -> list[ResourceEntry]:
    with resource_macbinary_files(source) as paths:
        entries = [entry for path in paths for entry in parse_macbinary_file(path)]
    return sorted(entries, key=_resource_sort_key)


def _resource_sort_key(entry: ResourceEntry) -> tuple[str, str, int, str]:
    return (
        entry.resource_file.casefold(),
        entry.type_code,
        entry.resource_id,
        entry.name,
    )


def decode_string_list(data: bytes) -> list[str]:
    count = _u16(data, 0, "STR# string count")
    offset = 2
    strings: list[str] = []
    for index in range(count):
        _need(data, offset, 1, f"STR# string {index + 1} length")
        length = data[offset]
        offset += 1
        _need(data, offset, length, f"STR# string {index + 1}")
        strings.append(_decode_mac_text(data[offset : offset + length]))
        offset += length
    if offset != len(data):
        raise ResourceFormatError(f"STR#: {len(data) - offset} trailing bytes")
    return strings


def decode_picture_bounds(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) < 10:
        return None
    top, left, bottom, right = struct.unpack_from(">hhhh", data, 2)
    if bottom < top or right < left:
        return None
    return left, top, right - left, bottom - top


def _candidate_widgets(view: ResourceEntry) -> list[WidgetRecord]:
    data = view.data
    candidates: list[WidgetRecord] = []
    for offset in range(4, len(data) - 39):
        type_bytes = data[offset : offset + 4]
        if type_bytes not in UI_TYPES:
            continue
        record_size = int.from_bytes(data[offset + 4 : offset + 8], "big")
        record_end = offset + 4 + record_size
        if record_size < 32 or record_end > len(data):
            continue
        payload = offset + 8
        class_length = data[payload]
        if class_length > 64:
            continue
        class_end = payload + 1 + class_length
        if class_end + 33 > len(data):
            continue
        class_bytes = data[payload + 1 : class_end]
        if any(byte < 0x20 or byte >= 0x7F for byte in class_bytes):
            continue
        tag_bytes = data[class_end : class_end + 4]
        if any(byte < 0x20 or byte >= 0x7F for byte in tag_bytes):
            continue
        sentinel = data[class_end + 5 : class_end + 9]
        if sentinel not in (b"\x7f\xff\xff\xff", b"\0\0\0\0"):
            continue
        y, x, height, width = struct.unpack_from(">iiii", data, class_end + 13)
        if any(not -10000 <= value <= 10000 for value in (x, y, width, height)):
            continue
        candidates.append(
            WidgetRecord(
                resource_file=view.resource_file,
                view_id=view.resource_id,
                view_name=view.name,
                offset=offset,
                record_end=record_end,
                type_code=type_bytes.decode("ascii"),
                class_name=class_bytes.decode("ascii"),
                tag=tag_bytes.decode("ascii"),
                x=x,
                y=y,
                width=width,
                height=height,
                parent_offset=None,
                parent_tag="",
                depth=0,
            )
        )

    resolved: list[WidgetRecord] = []
    by_offset = {record.offset: record for record in candidates}
    parent_by_offset: dict[int, int | None] = {}
    for record in candidates:
        containers = [
            other
            for other in candidates
            if other.offset < record.offset and other.record_end >= record.record_end
        ]
        parent = max(containers, key=lambda other: other.offset, default=None)
        parent_by_offset[record.offset] = None if parent is None else parent.offset

    def depth_of(offset: int) -> int:
        depth = 0
        seen: set[int] = set()
        parent = parent_by_offset[offset]
        while parent is not None:
            if parent in seen:
                raise ResourceFormatError(f"View {view.resource_id}: widget parent cycle")
            seen.add(parent)
            depth += 1
            parent = parent_by_offset[parent]
        return depth

    for record in candidates:
        parent_offset = parent_by_offset[record.offset]
        parent_tag = "" if parent_offset is None else by_offset[parent_offset].tag
        resolved.append(
            replace(
                record,
                parent_offset=parent_offset,
                parent_tag=parent_tag,
                depth=depth_of(record.offset),
            )
        )
    return resolved


def decode_widgets(resources: Sequence[ResourceEntry]) -> list[WidgetRecord]:
    widgets = [
        widget
        for resource in resources
        if resource.type_code == "View"
        for widget in _candidate_widgets(resource)
    ]
    return sorted(
        widgets,
        key=lambda widget: (
            widget.resource_file.casefold(),
            widget.view_id,
            widget.offset,
        ),
    )


def validate_startup_1500(widgets: Sequence[WidgetRecord]) -> list[str]:
    actual = [
        (
            widget.type_code,
            widget.tag,
            widget.class_name,
            widget.x,
            widget.y,
            widget.width,
            widget.height,
        )
        for widget in widgets
        if widget.resource_file == "Startup.rsrc" and widget.view_id == 1500
    ]
    if actual == EXPECTED_STARTUP_1500:
        return []
    return [
        "Startup.rsrc View 1500 does not match Windows event 0x5dc: "
        f"expected {EXPECTED_STARTUP_1500!r}, got {actual!r}"
    ]


def _write_csv(
    path: Path,
    fieldnames: Sequence[str],
    rows: Sequence[dict[str, object]],
    quoting: int = csv.QUOTE_MINIMAL,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=fieldnames, lineterminator="\n", quoting=quoting
        )
        writer.writeheader()
        writer.writerows(rows)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resource_set_sha256(resources: Sequence[ResourceEntry]) -> str:
    digest = hashlib.sha256()
    for resource in resources:
        for value in (resource.resource_file, resource.type_code, resource.name):
            encoded = value.encode("utf-8")
            digest.update(struct.pack(">I", len(encoded)))
            digest.update(encoded)
        digest.update(
            struct.pack(">hBI", resource.resource_id, resource.attributes, len(resource.data))
        )
        digest.update(resource.data)
    return digest.hexdigest()


def write_outputs(output_dir: Path, resources: Sequence[ResourceEntry]) -> dict[str, object]:
    resources = sorted(resources, key=_resource_sort_key)
    widgets = decode_widgets(resources)
    crosscheck_errors = validate_startup_1500(widgets)
    if crosscheck_errors:
        raise ResourceFormatError("\n".join(crosscheck_errors))

    views = [resource for resource in resources if resource.type_code == "View"]
    pictures = [resource for resource in resources if resource.type_code == "PICT"]
    string_groups = [resource for resource in resources if resource.type_code == "STR#"]
    text_styles = [resource for resource in resources if resource.type_code == "TxSt"]
    widget_counts: dict[tuple[str, int], int] = {}
    for widget in widgets:
        key = (widget.resource_file, widget.view_id)
        widget_counts[key] = widget_counts.get(key, 0) + 1

    _write_csv(
        output_dir / "views.csv",
        ["resource_file", "resource_id", "resource_id_hex", "name", "size", "sha256", "widget_count"],
        [
            {
                "resource_file": resource.resource_file,
                "resource_id": resource.resource_id,
                "resource_id_hex": f"0x{resource.resource_id & 0xFFFF:04x}",
                "name": resource.name,
                "size": len(resource.data),
                "sha256": _sha256(resource.data),
                "widget_count": widget_counts.get((resource.resource_file, resource.resource_id), 0),
            }
            for resource in views
        ],
    )
    _write_csv(
        output_dir / "widgets.csv",
        [
            "resource_file",
            "view_id",
            "view_id_hex",
            "view_name",
            "offset",
            "depth",
            "parent_offset",
            "parent_tag",
            "type_code",
            "class_name",
            "tag",
            "x",
            "y",
            "width",
            "height",
        ],
        [
            {
                "resource_file": widget.resource_file,
                "view_id": widget.view_id,
                "view_id_hex": f"0x{widget.view_id & 0xFFFF:04x}",
                "view_name": widget.view_name,
                "offset": f"0x{widget.offset:04x}",
                "depth": widget.depth,
                "parent_offset": "" if widget.parent_offset is None else f"0x{widget.parent_offset:04x}",
                "parent_tag": widget.parent_tag,
                "type_code": widget.type_code,
                "class_name": widget.class_name,
                "tag": widget.tag,
                "x": widget.x,
                "y": widget.y,
                "width": widget.width,
                "height": widget.height,
            }
            for widget in widgets
        ],
    )
    picture_rows: list[dict[str, object]] = []
    for resource in pictures:
        bounds = decode_picture_bounds(resource.data)
        picture_rows.append(
            {
                "resource_file": resource.resource_file,
                "resource_id": resource.resource_id,
                "resource_id_hex": f"0x{resource.resource_id & 0xFFFF:04x}",
                "name": resource.name,
                "x": "" if bounds is None else bounds[0],
                "y": "" if bounds is None else bounds[1],
                "width": "" if bounds is None else bounds[2],
                "height": "" if bounds is None else bounds[3],
                "size": len(resource.data),
                "sha256": _sha256(resource.data),
            }
        )
    _write_csv(
        output_dir / "pictures.csv",
        [
            "resource_file",
            "resource_id",
            "resource_id_hex",
            "name",
            "x",
            "y",
            "width",
            "height",
            "size",
            "sha256",
        ],
        picture_rows,
    )
    string_rows: list[dict[str, object]] = []
    for resource in string_groups:
        for index, text in enumerate(decode_string_list(resource.data), start=1):
            string_rows.append(
                {
                    "resource_file": resource.resource_file,
                    "group_id": resource.resource_id,
                    "group_id_hex": f"0x{resource.resource_id & 0xFFFF:04x}",
                    "group_name": resource.name,
                    "string_index": index,
                    "text": text,
                }
            )
    _write_csv(
        output_dir / "strings.csv",
        ["resource_file", "group_id", "group_id_hex", "group_name", "string_index", "text"],
        string_rows,
        quoting=csv.QUOTE_ALL,
    )
    _write_csv(
        output_dir / "text_styles.csv",
        ["resource_file", "resource_id", "resource_id_hex", "name", "size", "sha256"],
        [
            {
                "resource_file": resource.resource_file,
                "resource_id": resource.resource_id,
                "resource_id_hex": f"0x{resource.resource_id & 0xFFFF:04x}",
                "name": resource.name,
                "size": len(resource.data),
                "sha256": _sha256(resource.data),
            }
            for resource in text_styles
        ],
    )

    by_scoped_id: dict[tuple[str, int], list[ResourceEntry]] = {}
    for resource in resources:
        by_scoped_id.setdefault((resource.type_code, resource.resource_id), []).append(resource)
    collisions = [
        (key, values)
        for key, values in by_scoped_id.items()
        if len({value.resource_file for value in values}) > 1
    ]
    _write_csv(
        output_dir / "id_collisions.csv",
        ["type_code", "resource_id", "resource_id_hex", "occurrences", "resource_files", "names"],
        [
            {
                "type_code": key[0],
                "resource_id": key[1],
                "resource_id_hex": f"0x{key[1] & 0xFFFF:04x}",
                "occurrences": len(values),
                "resource_files": ";".join(value.resource_file for value in values),
                "names": ";".join(value.name for value in values),
            }
            for key, values in sorted(collisions, key=lambda item: (item[0][0], item[0][1]))
        ],
    )

    summary: dict[str, object] = {
        "format_version": EVIDENCE_VERSION,
        "resource_set_sha256": _resource_set_sha256(resources),
        "resource_files": sorted({resource.resource_file for resource in resources}),
        "resource_type_counts": dict(
            sorted(
                {
                    type_code: sum(resource.type_code == type_code for resource in resources)
                    for type_code in {resource.type_code for resource in resources}
                }.items()
            )
        ),
        "views": len(views),
        "widgets": len(widgets),
        "unique_widget_classes": len({widget.class_name for widget in widgets if widget.class_name}),
        "unique_widget_tags": len({widget.tag for widget in widgets}),
        "pictures": len(pictures),
        "named_pictures": sum(bool(resource.name) for resource in pictures),
        "string_groups": len(string_groups),
        "strings": len(string_rows),
        "text_styles": len(text_styles),
        "scoped_id_collisions": len(collisions),
        "windows_builder_crosscheck": {
            "resource_file": "Startup.rsrc",
            "view_id": 1500,
            "event_code": "0x5dc",
            "status": "match",
            "widget_count": len(EXPECTED_STARTUP_1500),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def check_outputs(output_dir: Path) -> int:
    required = [
        "summary.json",
        "views.csv",
        "widgets.csv",
        "pictures.csv",
        "strings.csv",
        "text_styles.csv",
        "id_collisions.csv",
    ]
    missing = [name for name in required if not (output_dir / name).is_file()]
    if missing:
        print(f"Mac resource evidence missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    if summary.get("format_version") != EVIDENCE_VERSION:
        errors.append(
            f"unsupported format_version: {summary.get('format_version')!r} "
            f"(expected {EVIDENCE_VERSION})"
        )
    minimums = {
        "views": 120,
        "widgets": 2000,
        "pictures": 2200,
        "named_pictures": 2200,
        "string_groups": 280,
        "strings": 3800,
        "text_styles": 300,
    }
    for field, minimum in minimums.items():
        actual = int(summary.get(field, 0))
        if actual < minimum:
            errors.append(f"{field} count too low: {actual} < {minimum}")
    crosscheck = summary.get("windows_builder_crosscheck", {})
    if not isinstance(crosscheck, dict) or crosscheck.get("status") != "match":
        errors.append("Startup.rsrc View 1500 Windows-builder cross-check is not marked match")

    csv_rows: dict[str, list[dict[str, str]]] = {}
    for name in required[1:]:
        with (output_dir / name).open(encoding="utf-8", newline="") as stream:
            csv_rows[name] = list(csv.DictReader(stream))
    expected_counts = {
        "views.csv": "views",
        "widgets.csv": "widgets",
        "pictures.csv": "pictures",
        "strings.csv": "strings",
        "text_styles.csv": "text_styles",
        "id_collisions.csv": "scoped_id_collisions",
    }
    for name, field in expected_counts.items():
        if len(csv_rows[name]) != summary.get(field):
            errors.append(
                f"{name} row count {len(csv_rows[name])} does not match "
                f"summary {field}={summary.get(field)!r}"
            )

    rows = csv_rows["widgets.csv"]
    startup_rows = [
        row
        for row in rows
        if row["resource_file"] == "Startup.rsrc" and int(row["view_id"]) == 1500
    ]
    actual = [
        (
            row["type_code"],
            row["tag"],
            row["class_name"],
            int(row["x"]),
            int(row["y"]),
            int(row["width"]),
            int(row["height"]),
        )
        for row in startup_rows
    ]
    if actual != EXPECTED_STARTUP_1500:
        errors.append("widgets.csv Startup.rsrc View 1500 does not match Windows event 0x5dc")

    print(
        "Mac resource evidence: "
        f"views={summary.get('views')} widgets={summary.get('widgets')} "
        f"pictures={summary.get('pictures')} strings={summary.get('strings')}"
    )
    if errors:
        print("Mac resource evidence check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Mac resource evidence check passed.")
    return 0


def default_workspace(repo_root: Path) -> Path:
    return (repo_root / "vendor" / "macos_codewarrior").resolve()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help="Retail directory/HFS ISO or directory containing extracted *.rsrc.bin files.",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get(
            "MACOS_CODEWARRIOR_WORKSPACE", str(default_workspace(repo_root))
        ),
        help="Mac evidence workspace; output is written below evidence/resources.",
    )
    parser.add_argument("--check", action="store_true", help="Validate committed evidence only.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = repo_root_from_file(__file__)
    workspace = resolve_repo_path(repo_root, args.workspace)
    output_dir = workspace / "evidence" / "resources"
    if args.check:
        return check_outputs(output_dir)
    if not args.source:
        raise SystemExit(
            "Set MACOS_IMPERIALISM_DUMP or pass --source pointing at the retail directory, "
            "HFS ISO, or extracted *.rsrc.bin directory"
        )
    source = resolve_repo_path(repo_root, args.source)
    if not source.exists():
        raise SystemExit(f"Missing Mac retail resource source: {source}")
    resources = load_resources(source)
    summary = write_outputs(output_dir, resources)
    print(f"[saved] {output_dir}")
    print(
        f"[info] views={summary['views']} widgets={summary['widgets']} "
        f"pictures={summary['pictures']} strings={summary['strings']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
