#!/usr/bin/env python3
"""Generate turn-event UI factory TUs from committed semantic resource evidence.

Mac View evidence owns Mac-backed screen semantics.  A small Windows semantic
file owns only screens that have no Mac counterpart.  The generator owns all
VC5-compatible source shape: local names, helper selection, and stack closure.
Neither retail binary is consulted during normal generation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

import yaml

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.turn_event_vocabulary import load_turn_event_vocabulary
from tools.workflow.macos_resource_evidence import validate_view_structure


MANIFEST_PATH = "config/ui_factory_codegen.yml"
IR_PATH = "vendor/macos_codewarrior/evidence/resources/ui_views.json"
STRINGS_PATH = "vendor/macos_codewarrior/evidence/resources/strings.csv"
TEXT_RESOURCES_PATH = "vendor/macos_codewarrior/evidence/resources/text_resources.json"
WINDOWS_VIEW_PATH = "config/ui_factory_windows_views.yml"
FORMAT_VERSION = 1

DEFAULT_CLASSES = {
    "view": "TView",
    "pict": "TPicture",
    "cntl": "TControl",
    "stat": "TStaticText",
    "clus": "TCluster",
    "tevw": "TTEView",
    "edit": "TEditText",
    "nmbr": "TNumberText",
    "radb": "TRadioPictureButton",
    "chkb": "TCzechBox",
    "wind": "TWindow",
    "fwnd": "TFloatWindow",
}

CLASS_ALIASES = {
    "TBookView": "TBook",
    "TDefenseNotesView": "TBook",
    "TExportsView": "TBook",
    "TForeignNotesView": "TBook",
    "TInteriorNotesView": "TBook",
    "TMerchantMarineView": "TBook",
    "TMiniDealBookView": "TBook",
    "TToolbarCluster": "TToolBarCluster",
    "TTreasuriesView": "TBook",
    "TMyWindow": "TWindow",
}

LAYOUT_FAMILIES = frozenset(
    ("pict", "cntl", "stat", "clus", "edit", "nmbr", "radb", "chkb")
)

# Font Manager IDs retained by the Windows builder ABI.  The historical
# binary-backed recipes confirm A/Geneva -> 3 and Helvetica -> 21; the other
# named entries are the corresponding classic system-font IDs.  An unknown or
# inherited font stays zero instead of inventing a Windows substitution.
MAC_FONT_FAMILY_IDS = {
    "": 0,
    "a": 3,
    "chicago": 0,
    "geneva": 3,
    "helvetica": 21,
    "palatino": 16,
}


@dataclass(frozen=True)
class UiResourceKey:
    resource_file: str
    view_id: int

    @classmethod
    def parse(cls, value: str) -> "UiResourceKey":
        resource_file, separator, raw_id = value.rpartition(":")
        if not separator or not resource_file:
            raise ValueError(f"invalid resource key {value!r}; expected FILE:ID")
        return cls(resource_file, int(raw_id, 0))

    def text(self) -> str:
        return f"{self.resource_file}:{self.view_id}"


@dataclass(frozen=True)
class UiCaseRecipe:
    event: int
    resource: UiResourceKey | None
    windows_view: str | None
    rejected: str
    evidence: str
    windows_overrides: tuple["UiNodeOverride", ...]


@dataclass(frozen=True)
class UiNodeOverride:
    node_id: str
    enabled: int
    evidence: str


@dataclass(frozen=True)
class UiFactoryRecipe:
    address: int
    name: str
    prototype: str
    cases: tuple[UiCaseRecipe, ...]

    @property
    def output_name(self) -> str:
        return f"turn_event_dialog_factory_{self.address:08x}.cpp"


@dataclass(frozen=True)
class UiStylePayload:
    word: int
    packed_color: int


@dataclass(frozen=True)
class UiTextPayload:
    resource_id: int
    resource_index: int
    value: str | None
    source: str | None
    mode: int
    flags: int
    point_size: int
    style_ref: int
    theme: int


@dataclass(frozen=True)
class UiNumberPayload:
    value: int
    minimum: int
    maximum: int


@dataclass(frozen=True)
class UiWindowColorPayload:
    behavior_flag: int
    triplet_flag: int
    foreground: int
    background: int


@dataclass(frozen=True)
class UiWindowPayload:
    flags: int
    style_type: int
    topmost: int
    resource_6f: int
    resource_6e: int
    captioned_frame: int
    resource_6c: int
    resource_71: int
    color: UiWindowColorPayload | None


@dataclass(frozen=True)
class UiSemanticFamily:
    frame_style: int | None = None
    content_insets: tuple[int, int, int, int] | None = None
    picture_id: int | None = None
    control_state: int | None = None
    style: UiStylePayload | None = None
    text: UiTextPayload | None = None
    max_chars: int | None = None
    number: UiNumberPayload | None = None
    cluster_value: int | None = None
    window: UiWindowPayload | None = None


@dataclass(frozen=True)
class UiSemanticNode:
    node_id: str
    type_code: str
    tag: str
    class_name: str
    parent_id: str | None
    geometry: tuple[int, int, int, int]
    state: int
    enabled: int
    input_gate: int
    child_hit_test: int
    control_value: int
    family: UiSemanticFamily
    source: str
    confidence: str

    @property
    def type_value(self) -> int:
        return int.from_bytes(self.type_code.encode("ascii"), "big")

    @property
    def tag_value(self) -> int:
        return int.from_bytes(self.tag.encode("ascii"), "big")


@dataclass(frozen=True)
class UiSemanticView:
    view_id: str
    event: int
    nodes: tuple[UiSemanticNode, ...]
    source: str


@dataclass(frozen=True)
class TextResources:
    strings: dict[tuple[str, int, int], str]
    styles: dict[tuple[str, int], dict]

    def __getitem__(self, key: tuple[str, int, int]) -> str:
        return self.strings[key]


_GAME_HEADER_CACHE: dict[str, dict[str, str]] = {}


def find_game_header(repo_root: Path, class_name: str) -> str | None:
    """Locate a class header under include/game (subsystem folders included);
    returns the include-path form (`game/<sub>/X.h`) or None."""
    key = str(repo_root)
    cache = _GAME_HEADER_CACHE.get(key)
    if cache is None:
        cache = {}
        for header in (repo_root / "include" / "game").rglob("*.h"):
            rel = header.relative_to(repo_root / "include").as_posix()
            cache.setdefault(header.stem, rel)
        _GAME_HEADER_CACHE[key] = cache
    return cache.get(class_name)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mapping(value: object, context: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{context}: expected an object")
    return value


def _sequence(value: object, length: int, context: str) -> list:
    if not isinstance(value, list) or len(value) != length:
        raise ValueError(f"{context}: expected a {length}-element list")
    return value


def _fourcc(value: object, context: str) -> str:
    text = str(value)
    if len(text) != 4 or any(ord(char) < 0x20 or ord(char) >= 0x7F for char in text):
        raise ValueError(f"{context}: expected a printable four-character code")
    return text


def load_recipes(repo_root: Path) -> list[UiFactoryRecipe]:
    data = yaml.safe_load((repo_root / MANIFEST_PATH).read_text(encoding="utf-8"))
    if data.get("format_version") != FORMAT_VERSION:
        raise ValueError(
            f"{MANIFEST_PATH}: unsupported format_version {data.get('format_version')!r}"
        )
    recipes: list[UiFactoryRecipe] = []
    addresses: set[int] = set()
    names: set[str] = set()
    for row in data.get("functions", []):
        address = int(row["address"])
        name = str(row["name"])
        if address in addresses:
            raise ValueError(f"{MANIFEST_PATH}: duplicate address 0x{address:08x}")
        if name in names:
            raise ValueError(f"{MANIFEST_PATH}: duplicate function name {name}")
        if "emission" in row:
            raise ValueError(
                f"{MANIFEST_PATH}: 0x{address:08x} stores forbidden emission choreography"
            )
        addresses.add(address)
        names.add(name)
        cases: list[UiCaseRecipe] = []
        events: set[int] = set()
        for case_row in row.get("cases", []):
            event = int(case_row["event"])
            if event in events:
                raise ValueError(
                    f"{MANIFEST_PATH}: 0x{address:08x} has duplicate event 0x{event:x}"
                )
            events.add(event)
            resource_raw = case_row.get("resource")
            resource = UiResourceKey.parse(str(resource_raw)) if resource_raw else None
            windows_view_raw = case_row.get("windows_view")
            windows_view = str(windows_view_raw) if windows_view_raw else None
            rejected = str(case_row.get("rejected", ""))
            evidence = str(case_row.get("evidence", ""))
            overrides: list[UiNodeOverride] = []
            raw_overrides = _mapping(
                case_row.get("windows_overrides", {}),
                f"{MANIFEST_PATH}: 0x{address:08x}/0x{event:x}/windows_overrides",
            )
            for raw_node_id, raw_override in raw_overrides.items():
                override_context = (
                    f"{MANIFEST_PATH}: 0x{address:08x}/0x{event:x}/{raw_node_id}"
                )
                override = _mapping(raw_override, override_context)
                if set(override) != {"enabled", "evidence"}:
                    raise ValueError(
                        f"{override_context}: expected enabled and evidence"
                    )
                override_evidence = str(override["evidence"])
                enabled = int(override["enabled"])
                if not override_evidence:
                    raise ValueError(f"{override_context}: evidence is required")
                if enabled not in (0, 1):
                    raise ValueError(f"{override_context}: enabled must be 0 or 1")
                overrides.append(
                    UiNodeOverride(f"0x{int(raw_node_id):04x}", enabled, override_evidence)
                )
            if sum((resource is not None, windows_view is not None, bool(rejected))) != 1:
                raise ValueError(
                    f"{MANIFEST_PATH}: 0x{address:08x}/0x{event:x} must have exactly "
                    "one of resource, windows_view, or rejected"
                )
            if rejected and not evidence:
                raise ValueError(
                    f"{MANIFEST_PATH}: rejected 0x{address:08x}/0x{event:x} "
                    "requires evidence"
                )
            cases.append(
                UiCaseRecipe(
                    event, resource, windows_view, rejected, evidence, tuple(overrides)
                )
            )
        if not cases:
            raise ValueError(f"{MANIFEST_PATH}: 0x{address:08x} has no cases")
        recipes.append(
            UiFactoryRecipe(address, name, str(row["prototype"]), tuple(cases))
        )
    return sorted(recipes, key=lambda recipe: recipe.address)


def load_ui_views(repo_root: Path) -> dict[UiResourceKey, dict]:
    data = json.loads((repo_root / IR_PATH).read_text(encoding="utf-8"))
    views: dict[UiResourceKey, dict] = {}
    for row in data.get("views", []):
        key = UiResourceKey(str(row["resource_file"]), int(row["view_id"]))
        if key in views:
            raise ValueError(f"{IR_PATH}: duplicate resource key {key.text()}")
        views[key] = row
    return views


def load_text_resources(repo_root: Path) -> TextResources:
    strings: dict[tuple[str, int, int], str] = {}
    with (repo_root / STRINGS_PATH).open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            key = (
                str(row["resource_file"]),
                int(row["group_id"]),
                int(row["string_index"]),
            )
            if key in strings:
                raise ValueError(f"{STRINGS_PATH}: duplicate string key {key!r}")
            strings[key] = str(row["text"])
    text_resources = json.loads(
        (repo_root / TEXT_RESOURCES_PATH).read_text(encoding="utf-8")
    )
    styles = {
        (str(row["resource_file"]), int(row["resource_id"])): row
        for row in text_resources["text_styles"]
    }
    return TextResources(strings, styles)


def _validate_windows_family(family: dict, context: str) -> None:
    allowed = {
        "frame_style",
        "content_insets",
        "picture_id",
        "control_state",
        "style",
        "text",
        "max_chars",
        "number",
        "cluster_value",
        "window",
    }
    unknown = sorted(set(family) - allowed)
    if unknown:
        raise ValueError(f"{context}: unknown semantic fields {', '.join(unknown)}")
    if "content_insets" in family:
        _sequence(family["content_insets"], 4, f"{context}/content_insets")
    if "style" in family:
        style = _mapping(family["style"], f"{context}/style")
        if set(style) != {"word", "packed_color"}:
            raise ValueError(f"{context}/style: expected word and packed_color")
    if "text" in family:
        text = _mapping(family["text"], f"{context}/text")
        required = {"resource_id", "resource_index", "source"}
        optional = {"mode", "flags", "point_size", "style_ref", "theme"}
        if not required <= set(text) or set(text) - (required | optional):
            raise ValueError(f"{context}/text: malformed semantic text binding")
    if "number" in family:
        number = _mapping(family["number"], f"{context}/number")
        if set(number) != {"value", "minimum", "maximum"}:
            raise ValueError(f"{context}/number: expected value, minimum, and maximum")
    if "window" in family:
        window = _mapping(family["window"], f"{context}/window")
        required = {
            "flags",
            "style_type",
            "topmost",
            "resource_6f",
            "resource_6e",
            "captioned_frame",
            "resource_6c",
            "resource_71",
        }
        if not required <= set(window) or set(window) - (required | {"color"}):
            raise ValueError(f"{context}/window: malformed semantic window payload")
        if "color" in window:
            color = _mapping(window["color"], f"{context}/window/color")
            if set(color) != {
                "behavior_flag",
                "triplet_flag",
                "foreground",
                "background",
            }:
                raise ValueError(f"{context}/window/color: malformed color payload")


def _parse_windows_family(family: dict, context: str) -> UiSemanticFamily:
    _validate_windows_family(family, context)
    style_row = family.get("style")
    style = (
        UiStylePayload(int(style_row["word"]), int(style_row["packed_color"]))
        if isinstance(style_row, dict)
        else None
    )
    text_row = family.get("text")
    text = (
        UiTextPayload(
            resource_id=int(text_row["resource_id"]),
            resource_index=int(text_row["resource_index"]),
            value=None,
            source=str(text_row["source"]),
            mode=int(text_row.get("mode", 0)),
            flags=int(text_row.get("flags", 0)),
            point_size=int(text_row.get("point_size", 0)),
            style_ref=int(text_row.get("style_ref", 0)),
            theme=int(text_row.get("theme", 1)),
        )
        if isinstance(text_row, dict)
        else None
    )
    number_row = family.get("number")
    number = (
        UiNumberPayload(
            int(number_row["value"]),
            int(number_row["minimum"]),
            int(number_row["maximum"]),
        )
        if isinstance(number_row, dict)
        else None
    )
    window_row = family.get("window")
    window = None
    if isinstance(window_row, dict):
        color_row = window_row.get("color")
        color = (
            UiWindowColorPayload(
                int(color_row["behavior_flag"]),
                int(color_row["triplet_flag"]),
                int(color_row["foreground"]),
                int(color_row["background"]),
            )
            if isinstance(color_row, dict)
            else None
        )
        window = UiWindowPayload(
            flags=int(window_row["flags"]),
            style_type=int(window_row["style_type"]),
            topmost=int(window_row["topmost"]),
            resource_6f=int(window_row["resource_6f"]),
            resource_6e=int(window_row["resource_6e"]),
            captioned_frame=int(window_row["captioned_frame"]),
            resource_6c=int(window_row["resource_6c"]),
            resource_71=int(window_row["resource_71"]),
            color=color,
        )
    insets_row = family.get("content_insets")
    return UiSemanticFamily(
        frame_style=(
            int(family["frame_style"]) if "frame_style" in family else None
        ),
        content_insets=(
            tuple(int(value) for value in insets_row)
            if isinstance(insets_row, list)
            else None
        ),
        picture_id=(int(family["picture_id"]) if "picture_id" in family else None),
        control_state=(
            int(family["control_state"]) if "control_state" in family else None
        ),
        style=style,
        text=text,
        max_chars=(int(family["max_chars"]) if "max_chars" in family else None),
        number=number,
        cluster_value=(
            int(family["cluster_value"]) if "cluster_value" in family else None
        ),
        window=window,
    )


def load_windows_views(repo_root: Path) -> dict[str, UiSemanticView]:
    data = yaml.safe_load((repo_root / WINDOWS_VIEW_PATH).read_text(encoding="utf-8"))
    if data.get("format_version") != FORMAT_VERSION:
        raise ValueError(
            f"{WINDOWS_VIEW_PATH}: unsupported format_version "
            f"{data.get('format_version')!r}"
        )
    unexpected = sorted(set(data) - {"format_version", "views"})
    if unexpected:
        raise ValueError(
            f"{WINDOWS_VIEW_PATH}: forbidden top-level fields {', '.join(unexpected)}"
        )
    view_rows = _mapping(data.get("views"), f"{WINDOWS_VIEW_PATH}: views")
    views: dict[str, UiSemanticView] = {}
    for view_id, row_value in view_rows.items():
        context = f"{WINDOWS_VIEW_PATH}: {view_id}"
        row = _mapping(row_value, context)
        evidence = _mapping(row.get("evidence"), f"{context}/evidence")
        evidence_start = int(evidence["start"])
        evidence_end = int(evidence["end"])
        if evidence_start >= evidence_end:
            raise ValueError(f"{context}/evidence: start must precede end")
        defaults = _mapping(row.get("defaults", {}), f"{context}/defaults")
        node_rows = row.get("nodes")
        if not isinstance(node_rows, list):
            raise ValueError(f"{context}/nodes: expected a list")
        nodes: list[UiSemanticNode] = []
        node_ids: set[str] = set()
        for node_value in node_rows:
            node_row = _mapping(node_value, f"{context}/nodes")
            node_id = str(node_row["id"])
            node_context = f"{context}/{node_id}"
            if node_id in node_ids:
                raise ValueError(f"{node_context}: duplicate node id")
            node_ids.add(node_id)
            geometry = _sequence(
                node_row.get("geometry"), 4, f"{node_context}/geometry"
            )
            family_row = _mapping(
                node_row.get("family", {}), f"{node_context}/family"
            )
            family = _parse_windows_family(family_row, f"{node_context}/family")
            node_evidence = int(node_row["evidence"])
            if not evidence_start <= node_evidence < evidence_end:
                raise ValueError(f"{node_context}: evidence lies outside view range")
            nodes.append(
                UiSemanticNode(
                    node_id=node_id,
                    type_code=_fourcc(node_row["type"], f"{node_context}/type"),
                    tag=_fourcc(node_row["tag"], f"{node_context}/tag"),
                    class_name=str(node_row["class"]),
                    parent_id=(
                        str(node_row["parent"])
                        if node_row.get("parent") is not None
                        else None
                    ),
                    geometry=tuple(int(value) for value in geometry),
                    state=int(node_row.get("state", defaults.get("state", 1))),
                    enabled=int(node_row.get("enabled", defaults.get("enabled", 1))),
                    input_gate=int(
                        node_row.get("input_gate", defaults.get("input_gate", 1))
                    ),
                    child_hit_test=int(
                        node_row.get(
                            "child_hit_test", defaults.get("child_hit_test", 1)
                        )
                    ),
                    control_value=int(
                        node_row.get(
                            "control_value", defaults.get("control_value", 0)
                        )
                    ),
                    family=family,
                    source=f"Windows: evidence 0x{node_evidence:08x}",
                    confidence="high",
                )
            )
        views[str(view_id)] = UiSemanticView(
            str(view_id),
            int(row["event"]),
            tuple(nodes),
            f"Windows evidence 0x{evidence_start:08x}-0x{evidence_end:08x}",
        )
    return views


def _resolved_class(node: dict) -> str:
    class_name = str(node.get("class_name") or "")
    if class_name:
        return CLASS_ALIASES.get(class_name, class_name)
    try:
        return DEFAULT_CLASSES[str(node["type_code"])]
    except KeyError as exc:
        raise ValueError(f"no Windows class for {node.get('type_code')!r}") from exc


def _fixed_24_8(value: int, context: str) -> int:
    if value % 0x100:
        raise ValueError(f"{context}: fixed 24.8 value 0x{value & 0xFFFFFFFF:x} is fractional")
    return value // 0x100


def _text_value(
    text_resources: TextResources,
    key: UiResourceKey,
    group_id: int,
    index: int,
) -> str:
    if index in (-1, 0xFFFF):
        return ""
    try:
        return text_resources[(key.resource_file, group_id, index)]
    except KeyError as exc:
        raise ValueError(
            f"{key.text()}: missing STR# {group_id} index {index} in {STRINGS_PATH}"
        ) from exc


def normalize_resource_view(
    key: UiResourceKey, view: dict, text_resources: TextResources
) -> UiSemanticView:
    nodes: list[UiSemanticNode] = []
    for row in view.get("nodes", []):
        offset = int(row["offset"])
        type_code = str(row["type_code"])
        class_name = _resolved_class(row)
        raw_family = row.get("family", {})
        frame_style: int | None = None
        content_insets: tuple[int, int, int, int] | None = None
        if type_code in LAYOUT_FAMILIES:
            raw_frame_style = raw_family.get("frame_style")
            insets = raw_family.get("content_insets")
            if (
                isinstance(raw_frame_style, int)
                and isinstance(insets, list)
                and len(insets) == 4
            ):
                frame_style = raw_frame_style
                content_insets = tuple(
                    _fixed_24_8(int(value), f"{key.text()} node 0x{offset:04x}")
                    for value in insets
                )
        raw_picture_id = raw_family.get("picture_id")
        picture_id = (
            int(raw_picture_id)
            if type_code in ("pict", "radb", "chkb")
            and isinstance(raw_picture_id, int)
            else None
        )
        raw_control_state = raw_family.get("control_state")
        control_state = (
            int(raw_control_state)
            if type_code in ("radb", "chkb") and isinstance(raw_control_state, int)
            else None
        )
        text: UiTextPayload | None = None
        style_id = raw_family.get("text_style_id")
        resolved_style = (
            text_resources.styles.get((key.resource_file, int(style_id)), {})
            if isinstance(style_id, int)
            else {}
        )
        font_name = str(resolved_style.get("font_name", ""))
        font_family = MAC_FONT_FAMILY_IDS.get(font_name.casefold(), 0)
        face_flags = int(resolved_style.get("face_flags", 0))
        point_size = int(resolved_style.get("point_size", 0))
        alignment = int(raw_family.get("text_alignment", 1))
        if type_code in ("stat", "nmbr"):
            group_id = int(raw_family.get("text_resource_id", 0))
            index = int(raw_family.get("text_resource_index", -1))
            text = UiTextPayload(
                group_id,
                index,
                _text_value(text_resources, key, group_id, index),
                None,
                font_family,
                face_flags,
                point_size,
                0,
                alignment,
            )
        max_chars: int | None = None
        if type_code == "edit":
            text = UiTextPayload(
                0,
                -1,
                "",
                None,
                font_family,
                face_flags,
                point_size,
                0,
                alignment,
            )
            max_chars = int(raw_family.get("max_char_count", 0xFF))
        number: UiNumberPayload | None = None
        if type_code == "nmbr":
            max_chars = int(raw_family["max_char_count"])
            number = UiNumberPayload(
                int(raw_family["number_value"]),
                int(raw_family["number_minimum"]),
                int(raw_family["number_maximum"]),
            )
        cluster_value = 0x20202020 if type_code == "clus" else None
        window: UiWindowPayload | None = None
        if type_code in ("wind", "fwnd"):
            window = UiWindowPayload(
                8,
                2,
                0,
                1,
                1,
                0,
                0,
                1,
                UiWindowColorPayload(1, 1, 0x20202020, 0x20202020),
            )
        family = UiSemanticFamily(
            frame_style=frame_style,
            content_insets=content_insets,
            picture_id=picture_id,
            control_state=control_state,
            text=text,
            max_chars=max_chars,
            number=number,
            cluster_value=cluster_value,
            window=window,
        )
        raw_hex = str(raw_family.get("raw_hex", ""))
        marker = type_code.encode("ascii").hex()
        confidence = "high" if raw_hex.startswith(marker) else "medium"
        geometry = row["geometry"]
        parent_offset = row.get("parent_offset")
        nodes.append(
            UiSemanticNode(
                node_id=f"0x{offset:04x}",
                type_code=type_code,
                tag=str(row["tag"]),
                class_name=class_name,
                parent_id=(
                    f"0x{int(parent_offset):04x}" if parent_offset is not None else None
                ),
                geometry=(
                    int(geometry["x"]),
                    int(geometry["y"]),
                    int(geometry["width"]),
                    int(geometry["height"]),
                ),
                state=int(row["state"]),
                # Windows traversal also uses enabled as a paint gate, so keep stateful
                # picture buttons renderable unless a case has binary-backed overrides.
                enabled=(
                    1
                    if class_name in ("TPictureButton", "T2PictureButton")
                    and int(row["state"]) != 0
                    else int(row["enabled"])
                ),
                input_gate=int(row["input_gate"]),
                child_hit_test=int(row["child_hit_test"]),
                control_value=int(row["control_value"]),
                family=family,
                source=f"Mac: {key.text()} node 0x{offset:04x}",
                confidence=confidence,
            )
        )
    return UiSemanticView(key.text(), key.view_id, tuple(nodes), f"Mac: {key.text()}")


def apply_case_windows_overrides(
    recipe: UiFactoryRecipe, case: UiCaseRecipe, view: UiSemanticView
) -> UiSemanticView:
    if not case.windows_overrides:
        return view
    overrides = {override.node_id: override for override in case.windows_overrides}
    known_nodes = {node.node_id for node in view.nodes}
    unknown_nodes = sorted(set(overrides) - known_nodes)
    if unknown_nodes:
        raise ValueError(
            f"{MANIFEST_PATH}: 0x{recipe.address:08x}/0x{case.event:x} "
            f"overrides unknown nodes {', '.join(unknown_nodes)}"
        )
    return replace(
        view,
        nodes=tuple(
            replace(
                node,
                enabled=overrides[node.node_id].enabled,
                source=f"{node.source}; Windows: {overrides[node.node_id].evidence}",
            )
            if node.node_id in overrides
            else node
            for node in view.nodes
        ),
    )


def _validate_semantic_view(
    repo_root: Path, context: str, view: UiSemanticView
) -> list[str]:
    errors: list[str] = []
    if not view.nodes:
        return [f"{context}: semantic view emits no nodes"]
    roots = sum(node.parent_id is None for node in view.nodes)
    if roots != 1:
        errors.append(f"{context}: semantic view must have exactly one root, found {roots}")
    open_ancestors: list[str] = []
    seen: set[str] = set()
    for node in view.nodes:
        while open_ancestors and open_ancestors[-1] != node.parent_id:
            open_ancestors.pop()
        if node.parent_id is not None and not open_ancestors:
            errors.append(
                f"{context}/{node.node_id}: parent {node.parent_id!r} is not an open ancestor"
            )
        if node.node_id in seen:
            errors.append(f"{context}/{node.node_id}: duplicate node id")
        seen.add(node.node_id)
        open_ancestors.append(node.node_id)
        if node.geometry[2] < 0 or node.geometry[3] < 0:
            errors.append(f"{context}/{node.node_id}: negative width or height")
        for name, value in (
            ("state", node.state),
            ("enabled", node.enabled),
            ("input_gate", node.input_gate),
            ("child_hit_test", node.child_hit_test),
        ):
            if value not in (0, 1):
                errors.append(f"{context}/{node.node_id}: {name} must be 0 or 1")
        if find_game_header(repo_root, node.class_name) is None:
            errors.append(
                f"{context}/{node.node_id}: missing include/game/**/{node.class_name}.h"
            )
        if not node.source:
            errors.append(f"{context}/{node.node_id}: missing semantic provenance")
        if node.confidence not in ("high", "medium", "low"):
            errors.append(f"{context}/{node.node_id}: invalid decoder confidence")
    return errors


def _squash_ws(text: str) -> str:
    return " ".join(text.split())


def validate(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
    windows_views: dict[str, UiSemanticView],
) -> list[str]:
    recipe_list = list(recipes)
    errors: list[str] = []
    referenced_windows: set[str] = set()
    declarations = _squash_ws(
        (repo_root / "include/game/turn_event_dialog_factory.h").read_text()
    )
    for recipe in recipe_list:
        if _squash_ws(recipe.prototype + ";") not in declarations:
            errors.append(
                f"0x{recipe.address:08x}: prototype does not match turn_event_dialog_factory.h"
            )
        for case in recipe.cases:
            context = f"0x{recipe.address:08x}/0x{case.event:x}"
            if case.rejected:
                continue
            if case.windows_view is not None:
                referenced_windows.add(case.windows_view)
                view = windows_views.get(case.windows_view)
                if view is None:
                    errors.append(f"{context}: missing Windows view {case.windows_view!r}")
                    continue
                if view.event != case.event:
                    errors.append(
                        f"{context}: Windows view has event 0x{view.event:x}"
                    )
            elif case.resource is not None:
                raw_view = views.get(case.resource)
                if raw_view is None:
                    errors.append(f"{context}: missing {case.resource.text()}")
                    continue
                if int(raw_view["view_id"]) != case.event:
                    errors.append(f"{context}: resource ID does not equal event ID")
                errors.extend(validate_view_structure(raw_view, require_cluster_counts=True))
                try:
                    view = normalize_resource_view(
                        case.resource, raw_view, text_resources
                    )
                except (KeyError, ValueError) as exc:
                    errors.append(f"{context}: {exc}")
                    continue
            else:
                errors.append(f"{context}: event neither emits nor rejects a view")
                continue
            errors.extend(_validate_semantic_view(repo_root, context, view))
    if len(recipe_list) != 17:
        errors.append(f"factory manifest must own 17 functions, found {len(recipe_list)}")
    if set(windows_views) != referenced_windows:
        errors.append(
            f"{WINDOWS_VIEW_PATH}: view keys do not exactly match manifest references"
        )
    return sorted(set(errors))


def _hex(value: int) -> str:
    if -10 < value < 10:
        return str(value)
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


def _tag(value: int, text: str) -> str:
    escaped = text.replace("'", "\\'")
    return f"0x{value:08x}u /* '{escaped}' */"


def _cpp_value(value: object) -> str:
    return _hex(value) if isinstance(value, int) else str(value)


def _cpp_args(values: Iterable[object]) -> str:
    return ", ".join(_cpp_value(value) for value in values)


def _cpp_string(value: str) -> str:
    pieces: list[str] = []
    for byte in value.encode("cp1252", errors="replace"):
        if byte == 0x22:
            pieces.append('\\"')
        elif byte == 0x5C:
            pieces.append("\\\\")
        elif byte == 0x0A:
            pieces.append("\\n")
        elif byte == 0x0D:
            pieces.append("\\r")
        elif byte == 0x09:
            pieces.append("\\t")
        elif 0x20 <= byte < 0x7F:
            pieces.append(chr(byte))
        else:
            pieces.append(f"\\{byte:03o}")
    return '"' + "".join(pieces) + '"'


def _semantic_variable_names(view: UiSemanticView) -> dict[str, str]:
    occurrences: dict[str, int] = {}
    names: dict[str, str] = {}
    for node in view.nodes:
        tag = "".join(
            char.lower() if char.isalnum() else "_" for char in node.tag
        ).strip("_")
        base = f"node_{tag or 'view'}"
        occurrences[base] = occurrences.get(base, 0) + 1
        occurrence = occurrences[base]
        names[node.node_id] = base if occurrence == 1 else f"{base}_{occurrence}"
    return names


def _emit_semantic_view(
    lines: list[str], view: UiSemanticView, indent: str
) -> tuple[set[str], dict[str, dict[str, object]]]:
    classes: set[str] = set()
    stack: list[UiSemanticNode] = []
    variables = _semantic_variable_names(view)
    source_map: dict[str, dict[str, object]] = {}

    def pop_node() -> None:
        closed = stack.pop()
        lines.append(
            f"{indent}PopUiResourcePoolNode({_tag(closed.tag_value, closed.tag)});"
        )

    for node in view.nodes:
        while stack and stack[-1].node_id != node.parent_id:
            pop_node()
        parent = stack[-1] if stack else None
        variable = variables[node.node_id]
        x, y, width, height = node.geometry
        classes.add(node.class_name)
        start_line = len(lines) + 1
        lines.extend(
            (
                "",
                f"{indent}// {node.source}; confidence {node.confidence}.",
                f"{indent}{node.class_name}* {variable} = new {node.class_name}();",
            )
        )
        parent_tag = _tag(parent.tag_value, parent.tag) if parent is not None else "0"
        lines.append(
            f"{indent}RegisterUiResourceEntry({_tag(node.type_value, node.type_code)}, "
            f"{_tag(node.tag_value, node.tag)}, {variable}, {_hex(x)}, {_hex(y)}, "
            f"{_hex(width)}, {_hex(height)}, {_hex(node.state)}, {_hex(node.enabled)}, "
            f"{parent_tag}, {_hex(node.control_value)});"
        )
        lines.append(
            f"{indent}SetUiResourceStateFlags({_hex(node.input_gate)}, "
            f"{_hex(node.child_hit_test)});"
        )
        family = node.family
        if family.frame_style is not None and family.content_insets is not None:
            lines.append(
                f"{indent}SetUiResourceEventNumberAndInsets({_hex(family.frame_style)}, "
                f"{_cpp_args(family.content_insets)});"
            )
        if family.picture_id is not None:
            lines.append(
                f"{indent}SetUiResourceContextPictureId({_hex(family.picture_id)});"
            )
        if family.control_state is not None:
            lines.append(
                f"{indent}{variable}->HiliteState("
                f"{_hex(family.control_state)}, 0);"
            )
        if family.style is not None:
            lines.append(
                f"{indent}ReplaceUiResourceContextPairBuffer("
                f"{_cpp_value(family.style.word)}, "
                f"{_cpp_value(family.style.packed_color)});"
            )
        if family.text is not None:
            text = family.text
            source = (
                _cpp_string(text.value)
                if text.value is not None
                else str(text.source)
            )
            lines.append(
                f"{indent}BindUiResourceTextAndStyle("
                f"{_cpp_args((text.resource_id, text.resource_index, source, text.mode, text.flags, text.point_size, text.style_ref, text.theme))});"
            )
        if family.max_chars is not None:
            lines.append(
                f"{indent}SetUiResourceContextMaxCharCount({_hex(family.max_chars)});"
            )
        if family.number is not None:
            lines.append(
                f"{indent}SetUiResourceContextNumberValueAndRange("
                f"{_cpp_args((family.number.value, family.number.minimum, family.number.maximum))});"
            )
        if family.cluster_value is not None:
            lines.append(
                f"{indent}SetUiResourceContextStringCode("
                f"{_cpp_value(family.cluster_value)});"
            )
        if family.window is not None:
            window = family.window
            lines.append(
                f"{indent}SetUiResourceContextFlagsAndMetrics("
                f"{_cpp_args((window.flags, window.style_type, window.topmost, window.resource_6f, window.resource_6e, window.captioned_frame, window.resource_6c, window.resource_71))});"
            )
            if window.color is not None:
                color = window.color
                lines.append(
                    f"{indent}ApplyUiResourceColorTripletFromContext("
                    f"{_cpp_args((color.behavior_flag, color.triplet_flag, color.foreground, color.background))});"
                )
        lines.append(f"{indent}ClearUiResourceContext();")
        source_entry: dict[str, object] = {
            "tag": node.tag,
            "class": node.class_name,
            "source": node.source,
            "confidence": node.confidence,
            "generated_lines": [start_line, len(lines)],
        }
        if family.text is not None:
            source_entry["text_style"] = {
                "font_family": family.text.mode,
                "face_flags": family.text.flags,
                "point_size": family.text.point_size,
                "alignment": family.text.theme,
            }
        source_map[node.node_id] = source_entry
        stack.append(node)
    while stack:
        pop_node()
    return classes, source_map


def _render_factory_with_map(
    recipe: UiFactoryRecipe,
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
    windows_views: dict[str, UiSemanticView],
    annotation_kind: str = "FUNCTION",
) -> tuple[str, dict[str, object]]:
    vocabulary_by_event, _ = load_turn_event_vocabulary(
        repo_root_from_file(__file__, levels_up=1)
    )
    body: list[str] = []
    classes: set[str] = set()
    case_maps: dict[str, object] = {}
    if annotation_kind != "none":
        body.append(f"// {annotation_kind}: IMPERIALISM 0x{recipe.address:08x}")
    body.extend((recipe.prototype + " {", "  g_pUiResourceHead = 0;"))
    if len(recipe.cases) == 1:
        body.extend(
            (
                "  if (static_cast<unsigned short>(nEventCode) != "
                f"{vocabulary_by_event[recipe.cases[0].event]}) {{",
                "    return 0;",
                "  }",
            )
        )
    else:
        body.append("  switch (static_cast<unsigned short>(nEventCode)) {")
    for case in recipe.cases:
        indent = "  " if len(recipe.cases) == 1 else "    "
        if len(recipe.cases) > 1:
            body.append(f"  case {vocabulary_by_event[case.event]}: {{")
        if case.evidence and not case.rejected:
            body.append(f"{indent}// FUNCTIONAL_PARITY: {case.evidence}.")
        if case.resource is not None:
            view = normalize_resource_view(
                case.resource, views[case.resource], text_resources
            )
        elif case.windows_view is not None:
            view = windows_views[case.windows_view]
        else:
            body.extend(
                (
                    f"{indent}// REJECTED: {case.rejected}; evidence {case.evidence}.",
                    f"{indent}return 0;",
                )
            )
            view = None
        if view is not None:
            view = apply_case_windows_overrides(recipe, case, view)
            case_classes, node_map = _emit_semantic_view(body, view, indent)
            classes.update(case_classes)
            case_maps[f"0x{case.event:04x}"] = {
                "source": view.source,
                "evidence": case.evidence,
                "nodes": node_map,
            }
        if len(recipe.cases) > 1:
            body.extend(("    break;", "  }"))
    if len(recipe.cases) > 1:
        body.extend(("  default:", "    return 0;", "  }"))
    body.extend(
        (
            "",
            "#ifdef IMPERIALISM_RUNTIME_TESTS",
            "  RuntimeTestObserveBuiltUiTree(",
            "      static_cast<unsigned short>(nEventCode), g_pUiResourceHead);",
            "#endif",
            "",
            "  if (g_pUiResourceHead != 0) {",
            "    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);",
            "  }",
            "  return g_pUiResourceHead;",
            "}",
        )
    )
    includes = [
        '#include "game/turn_event_dialog_factory.h"',
        '#include "game/turn_event_codes.h"',
        '#include "game/core/global_data_tables.h"',
        '#include "game/app/ui_resource_builder.h"',
    ]
    _codegen_repo_root = repo_root_from_file(__file__, levels_up=1)
    includes.extend(
        f'#include "{find_game_header(_codegen_repo_root, class_name) or f"game/{class_name}.h"}"'
        for class_name in sorted(classes)
        if class_name != "TView"
    )
    prefix = ["// AUTOGENERATED FROM SEMANTIC UI EVIDENCE. DO NOT EDIT.", *includes, ""]
    line_offset = len(prefix)
    for case_map in case_maps.values():
        for node_map in case_map["nodes"].values():
            node_map["generated_lines"] = [
                node_map["generated_lines"][0] + line_offset,
                node_map["generated_lines"][1] + line_offset,
            ]
    text = "\n".join(prefix + body) + "\n"
    return text, {
        "function": f"0x{recipe.address:08x}",
        "name": recipe.name,
        "generated_file": recipe.output_name,
        "cases": case_maps,
    }


def render_factory(
    recipe: UiFactoryRecipe,
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
    windows_views: dict[str, UiSemanticView],
    annotation_kind: str = "FUNCTION",
) -> str:
    return _render_factory_with_map(
        recipe, views, text_resources, windows_views, annotation_kind
    )[0]


def _write_if_changed(path: Path, content: str) -> None:
    encoded = content.encode("utf-8")
    if path.is_file() and path.read_bytes() == encoded:
        return
    path.write_bytes(encoded)


def write_generated(
    repo_root: Path,
    output_dir: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
    windows_views: dict[str, UiSemanticView],
    annotation_kind: str = "FUNCTION",
) -> dict:
    recipe_list = list(recipes)
    output_dir.mkdir(parents=True, exist_ok=True)
    expected = {recipe.output_name for recipe in recipe_list}
    for stale in output_dir.glob("turn_event_dialog_factory_*.cpp"):
        if stale.name not in expected:
            stale.unlink()
    files: list[dict[str, object]] = []
    source_maps: dict[str, object] = {}
    for recipe in recipe_list:
        text, source_map = _render_factory_with_map(
            recipe, views, text_resources, windows_views, annotation_kind
        )
        _write_if_changed(output_dir / recipe.output_name, text)
        files.append(
            {
                "address": f"0x{recipe.address:08x}",
                "name": recipe.name,
                "file": recipe.output_name,
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
        source_maps[f"0x{recipe.address:08x}"] = source_map
    source_map_text = json.dumps(
        {"format_version": FORMAT_VERSION, "functions": source_maps},
        indent=2,
        sort_keys=True,
    ) + "\n"
    _write_if_changed(output_dir / "_source_map.json", source_map_text)
    manifest = {
        "format_version": FORMAT_VERSION,
        "manifest_sha256": _sha256(repo_root / MANIFEST_PATH),
        "ui_ir_sha256": _sha256(repo_root / IR_PATH),
        "strings_sha256": _sha256(repo_root / STRINGS_PATH),
        "windows_view_sha256": _sha256(repo_root / WINDOWS_VIEW_PATH),
        "source_map_sha256": hashlib.sha256(source_map_text.encode()).hexdigest(),
        "files": files,
    }
    _write_if_changed(
        output_dir / "_manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )
    return manifest


def generated_output_paths(repo_root: Path) -> list[str]:
    return [
        f"build-msvc500/generated/ui/{recipe.output_name}"
        for recipe in load_recipes(repo_root)
    ]


def generated_claim_rows(repo_root: Path) -> list[dict[str, object]]:
    return [
        {
            "address": recipe.address,
            "kind": "FUNCTION",
            "file": f"build-msvc500/generated/ui/{recipe.output_name}",
            "line": 0,
            "name": recipe.name,
            "prototype": recipe.prototype,
            "origin": "generated",
        }
        for recipe in load_recipes(repo_root)
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--gen-dir", default="build-msvc500/generated/ui")
    parser.add_argument("--function", help="Generate only one factory address")
    parser.add_argument("--view", help="Print one committed Mac View as FILE:ID JSON")
    parser.add_argument(
        "--explain",
        nargs="+",
        metavar="KEY",
        help="Explain FUNCTION EVENT [NODE-OFFSET-OR-TAG] from the generated source map",
    )
    parser.add_argument(
        "--triage-map",
        metavar="FUNCTION",
        help="Summarize case/node source-map coverage for one generated factory",
    )
    parser.add_argument(
        "--annotation-kind",
        default="FUNCTION",
        choices=("STUB", "FUNCTION", "none"),
    )
    return parser.parse_args()


def _load_generated_source_map(repo_root: Path, gen_dir: str) -> dict:
    path = resolve_repo_path(repo_root, gen_dir) / "_source_map.json"
    if not path.is_file():
        raise SystemExit(f"Missing {path}; run just ui-codegen first")
    return json.loads(path.read_text(encoding="utf-8"))


def _function_map(source_map: dict, raw_address: str) -> dict:
    key = f"0x{int(raw_address, 0):08x}"
    function = source_map.get("functions", {}).get(key)
    if function is None:
        raise SystemExit(f"No generated UI factory at {key}")
    return function


def _print_source_map_explanation(
    repo_root: Path, gen_dir: str, keys: list[str]
) -> None:
    if len(keys) not in (2, 3):
        raise SystemExit("--explain expects FUNCTION EVENT [NODE-OFFSET-OR-TAG]")
    source_map = _load_generated_source_map(repo_root, gen_dir)
    function = _function_map(source_map, keys[0])
    event_key = f"0x{int(keys[1], 0):04x}"
    case = function.get("cases", {}).get(event_key)
    if case is None:
        raise SystemExit(f"{function['function']} has no generated case {event_key}")
    nodes = case.get("nodes", {})
    selected = list(nodes.items())
    if len(keys) == 3:
        selector = keys[2]
        try:
            node_key = f"0x{int(selector, 0):04x}"
        except ValueError:
            node_key = ""
        selected = [
            (key, node)
            for key, node in selected
            if key == node_key or node.get("tag") == selector
        ]
        if not selected:
            raise SystemExit(f"{function['function']}/{event_key}: no node {selector!r}")
    generated = resolve_repo_path(repo_root, gen_dir) / function["generated_file"]
    print(f"{function['function']} {function['name']} / case {event_key}")
    print(f"source: {case['source']}")
    for node_key, node in selected:
        start, end = node["generated_lines"]
        print(
            f"{node_key} tag={node['tag']!r} class={node['class']} "
            f"confidence={node['confidence']} {generated}:{start}-{end}"
        )
        print(f"  evidence: {node['source']}")


def _print_source_map_triage(repo_root: Path, gen_dir: str, raw_address: str) -> None:
    source_map = _load_generated_source_map(repo_root, gen_dir)
    function = _function_map(source_map, raw_address)
    platform_path = repo_root / "docs/reference/ui_platform_diff.json"
    platform_report = (
        json.loads(platform_path.read_text(encoding="utf-8"))
        if platform_path.is_file()
        else {"functions": {}}
    )
    platform_function = platform_report.get("functions", {}).get(function["function"], {})
    print(f"{function['function']} {function['name']}")
    print(f"generated: {resolve_repo_path(repo_root, gen_dir) / function['generated_file']}")
    for event, case in sorted(function.get("cases", {}).items()):
        nodes = case.get("nodes", {})
        confidence_counts: dict[str, int] = {}
        for node in nodes.values():
            confidence = str(node["confidence"])
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        counts = ", ".join(
            f"{name}={count}" for name, count in sorted(confidence_counts.items())
        )
        platform_case = platform_function.get("cases", {}).get(event, {})
        platform_classification = platform_case.get("classification", "unavailable")
        delta_counts: dict[str, int] = {}
        for node in platform_case.get("nodes", {}).values():
            classification = str(node["classification"])
            if classification != "same_semantics":
                delta_counts[classification] = delta_counts.get(classification, 0) + 1
        deltas = ", ".join(
            f"{name}={count}" for name, count in sorted(delta_counts.items())
        ) or "none"
        print(
            f"{event}: nodes={len(nodes)} {counts}; platform={platform_classification} "
            f"deltas={deltas}; {case['source']}"
        )


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=1)
    recipes = load_recipes(repo_root)
    views = load_ui_views(repo_root)
    text_resources = load_text_resources(repo_root)
    windows_views = load_windows_views(repo_root)
    errors = validate(repo_root, recipes, views, text_resources, windows_views)
    if errors:
        print("UI codegen validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1
    if args.view:
        key = UiResourceKey.parse(args.view)
        if key not in views:
            raise SystemExit(f"No committed Mac View {key.text()}")
        print(json.dumps(views[key], indent=2, sort_keys=True))
        return 0
    if args.explain:
        _print_source_map_explanation(repo_root, args.gen_dir, args.explain)
        return 0
    if args.triage_map:
        _print_source_map_triage(repo_root, args.gen_dir, args.triage_map)
        return 0
    selected = recipes
    if args.function:
        address = int(args.function, 0)
        selected = [recipe for recipe in recipes if recipe.address == address]
        if not selected:
            raise SystemExit(f"No UI factory at 0x{address:08x}")
    if args.check:
        print(
            f"UI codegen check passed: {len(recipes)} functions, "
            f"{sum(len(recipe.cases) for recipe in recipes)} cases"
        )
        return 0
    output_dir = resolve_repo_path(repo_root, args.gen_dir)
    if args.function:
        output_dir.mkdir(parents=True, exist_ok=True)
        for recipe in selected:
            text = render_factory(
                recipe,
                views,
                text_resources,
                windows_views,
                args.annotation_kind,
            )
            _write_if_changed(output_dir / recipe.output_name, text)
        print(f"Wrote {len(selected)} UI factory TUs to {output_dir}")
        return 0
    manifest = write_generated(
        repo_root,
        output_dir,
        selected,
        views,
        text_resources,
        windows_views,
        args.annotation_kind,
    )
    print(f"Wrote {len(manifest['files'])} UI factory TUs to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
