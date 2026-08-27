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
WINDOWS_DELTA_PATH = "config/ui_platform_deltas.yml"
RUST_UI_PATH = "../rust/crates/imperialism-app/src/ui/generated.rs"

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
    windows_overrides: tuple["WindowsNodeOverride", ...]


@dataclass(frozen=True)
class WindowsNodeOverride:
    node_id: str
    enabled: int | None
    control_value: int | None
    content_insets: tuple[int, int, int, int] | None
    style_word: int | None
    packed_color: int | None
    text_source: str | None
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
    color_index: int | None = None
    shadow_color_index: int | None = None
    shadow_offset: tuple[int, int] = (0, 0)
    center_vertically: bool = False


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


@dataclass(frozen=True)
class UiTextPropertyPatch:
    resource: UiResourceKey
    node_id: str
    tag: str
    font_family: int
    face_flags: int
    point_size: int
    alignment: int
    evidence: str
    color_index: int | None = None
    shadow_color_index: int | None = None
    shadow_offset: tuple[int, int] | None = None
    resource_id: int | None = None
    resource_index: int | None = None
    resource_file: str | None = None
    geometry_top_delta: int | None = None


@dataclass(frozen=True)
class UiChildNodePatch:
    resource: UiResourceKey
    parent_id: str
    parent_tag: str
    type_code: str
    tag: str
    class_name: str
    geometry: tuple[int, int, int, int]
    family: UiSemanticFamily
    evidence: str


@dataclass(frozen=True)
class CityBuildingVisual:
    slot: str
    origin: tuple[int, int]
    draw_order: int
    dialog: UiResourceKey


@dataclass(frozen=True)
class CityBuildingVisuals:
    view: UiResourceKey
    visuals: tuple[CityBuildingVisual, ...]


@dataclass(frozen=True)
class CityBuildingActionVisual:
    slot: str
    level: int
    picture_id: int
    frame_count: int
    origin: tuple[int, int]
    frame_size: tuple[int, int]


@dataclass(frozen=True)
class CityBuildingActionVisuals:
    view: UiResourceKey
    actions: tuple[CityBuildingActionVisual, ...]


@dataclass(frozen=True)
class CityRowControls:
    cluster: str
    button: str


@dataclass(frozen=True)
class CityShipyardRowControls:
    cluster: str
    button: str
    overlay_left: int


@dataclass(frozen=True)
class CityIndustryPageControls:
    slot: str
    order_tags: tuple[str, ...]
    stocks: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class CityDialogControls:
    armory_rows: tuple[CityRowControls, ...]
    university_rows: tuple[CityRowControls, ...]
    shipyard_rows: tuple[CityShipyardRowControls, ...]
    shipyard_stat_origins: tuple[tuple[int, int], ...]
    training_orders: tuple[str, ...]
    food_order: str
    power_order: str
    transport_order: str
    population_order: str
    warehouse_stocks: tuple[str, ...]
    industry: tuple[CityIndustryPageControls, ...]


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
            overrides: list[WindowsNodeOverride] = []
            raw_overrides = _mapping(
                case_row.get("windows_overrides", {}),
                f"{MANIFEST_PATH}: 0x{address:08x}/0x{event:x}/windows_overrides",
            )
            for raw_node_id, raw_override in raw_overrides.items():
                override_context = (
                    f"{MANIFEST_PATH}: 0x{address:08x}/0x{event:x}/{raw_node_id}"
                )
                override = _mapping(raw_override, override_context)
                allowed_override_fields = {
                    "enabled",
                    "control_value",
                    "content_insets",
                    "style",
                    "text_source",
                    "evidence",
                }
                if set(override) - allowed_override_fields or "evidence" not in override:
                    raise ValueError(
                        f"{override_context}: expected enabled and/or style plus evidence"
                    )
                override_evidence = str(override["evidence"])
                enabled = int(override["enabled"]) if "enabled" in override else None
                control_value = (
                    int(override["control_value"])
                    if "control_value" in override
                    else None
                )
                content_insets = None
                if "content_insets" in override:
                    content_insets = tuple(
                        int(value)
                        for value in _sequence(
                            override["content_insets"],
                            4,
                            f"{override_context}/content_insets",
                        )
                    )
                style = override.get("style")
                style_word = None
                packed_color = None
                if style is not None:
                    style_mapping = _mapping(style, f"{override_context}/style")
                    if set(style_mapping) != {"word", "packed_color"}:
                        raise ValueError(
                            f"{override_context}/style: expected word and packed_color"
                        )
                    style_word = int(style_mapping["word"])
                    packed_color = int(style_mapping["packed_color"])
                text_source = (
                    str(override["text_source"])
                    if "text_source" in override
                    else None
                )
                if (
                    enabled is None
                    and control_value is None
                    and content_insets is None
                    and style is None
                    and text_source is None
                ):
                    raise ValueError(f"{override_context}: expected a semantic override")
                if not override_evidence:
                    raise ValueError(f"{override_context}: evidence is required")
                if enabled is not None and enabled not in (0, 1):
                    raise ValueError(f"{override_context}: enabled must be 0 or 1")
                overrides.append(
                    WindowsNodeOverride(
                        f"0x{int(raw_node_id):04x}",
                        enabled,
                        control_value,
                        content_insets,
                        style_word,
                        packed_color,
                        text_source,
                        override_evidence,
                    )
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


def load_windows_text_property_patches(repo_root: Path) -> tuple[UiTextPropertyPatch, ...]:
    data = yaml.safe_load((repo_root / WINDOWS_DELTA_PATH).read_text(encoding="utf-8"))
    rows = data.get("node_property_patches", [])
    if not isinstance(rows, list):
        raise ValueError(f"{WINDOWS_DELTA_PATH}: node_property_patches must be a list")
    patches: list[UiTextPropertyPatch] = []
    identities: set[tuple[UiResourceKey, str]] = set()
    for index, raw_row in enumerate(rows):
        context = f"{WINDOWS_DELTA_PATH}: node_property_patches[{index}]"
        row = _mapping(raw_row, context)
        if set(row) != {"view", "node", "tag", "properties", "evidence"}:
            raise ValueError(f"{context}: malformed scoped node property patch")
        resource = UiResourceKey.parse(str(row["view"]))
        node_id = f"0x{int(str(row['node']), 0):04x}"
        tag = _fourcc(row["tag"], f"{context}/tag")
        properties = _mapping(row["properties"], f"{context}/properties")
        allowed_properties = {"text", "geometry"}
        extra_properties = set(properties) - allowed_properties
        if extra_properties or "text" not in properties:
            raise ValueError(
                f"{context}/properties: expected text with optional geometry, "
                f"not {sorted(properties)!r}"
            )
        text = _mapping(properties["text"], f"{context}/properties/text")
        required = {"font_family", "face_flags", "point_size", "alignment"}
        optional = {
            "color_index",
            "shadow_color_index",
            "shadow_offset",
            "resource_id",
            "resource_index",
            "resource_file",
        }
        if not required <= set(text) or set(text) - (required | optional):
            raise ValueError(
                f"{context}/properties/text: expected {sorted(required)!r} "
                f"with optional {sorted(optional)!r}"
            )
        shadow_offset = None
        if "shadow_offset" in text:
            offset = _sequence(
                text["shadow_offset"], 2, f"{context}/properties/text/shadow_offset"
            )
            shadow_offset = (int(offset[0]), int(offset[1]))
        if ("shadow_color_index" in text) != (shadow_offset is not None):
            raise ValueError(
                f"{context}/properties/text: shadow_color_index and shadow_offset "
                "must be declared together"
            )
        if ("resource_id" in text) != ("resource_index" in text):
            raise ValueError(
                f"{context}/properties/text: resource_id and resource_index "
                "must be declared together"
            )
        if "resource_file" in text and "resource_id" not in text:
            raise ValueError(
                f"{context}/properties/text: resource_file requires resource_id"
            )
        geometry_top_delta = None
        if "geometry" in properties:
            geometry = _mapping(properties["geometry"], f"{context}/properties/geometry")
            if set(geometry) != {"top"}:
                raise ValueError(
                    f"{context}/properties/geometry: only a CRect top delta is supported"
                )
            geometry_top_delta = int(geometry["top"])
        evidence = str(row["evidence"]).strip()
        if not evidence:
            raise ValueError(f"{context}: evidence is required")
        identity = (resource, node_id)
        if identity in identities:
            raise ValueError(f"{context}: duplicate patch for {resource.text()} {node_id}")
        identities.add(identity)
        patches.append(
            UiTextPropertyPatch(
                resource,
                node_id,
                tag,
                int(text["font_family"]),
                int(text["face_flags"]),
                int(text["point_size"]),
                int(text["alignment"]),
                evidence,
                color_index=(
                    int(text["color_index"]) if "color_index" in text else None
                ),
                shadow_color_index=(
                    int(text["shadow_color_index"])
                    if "shadow_color_index" in text
                    else None
                ),
                shadow_offset=shadow_offset,
                resource_id=(int(text["resource_id"]) if "resource_id" in text else None),
                resource_index=(
                    int(text["resource_index"]) if "resource_index" in text else None
                ),
                resource_file=(str(text["resource_file"]) if "resource_file" in text else None),
                geometry_top_delta=geometry_top_delta,
            )
        )
    return tuple(
        sorted(
            patches,
            key=lambda patch: (
                patch.resource.resource_file,
                patch.resource.view_id,
                int(patch.node_id, 16),
            ),
        )
    )


def load_windows_child_node_patches(repo_root: Path) -> tuple[UiChildNodePatch, ...]:
    data = yaml.safe_load((repo_root / WINDOWS_DELTA_PATH).read_text(encoding="utf-8"))
    rows = data.get("windows_child_nodes", [])
    if not isinstance(rows, list):
        raise ValueError(f"{WINDOWS_DELTA_PATH}: windows_child_nodes must be a list")
    patches: list[UiChildNodePatch] = []
    identities: set[tuple[UiResourceKey, str, str]] = set()
    for index, raw_row in enumerate(rows):
        context = f"{WINDOWS_DELTA_PATH}: windows_child_nodes[{index}]"
        row = _mapping(raw_row, context)
        expected = {
            "view",
            "parent",
            "type",
            "tag",
            "class",
            "geometry",
            "family",
            "evidence",
        }
        if set(row) != expected:
            raise ValueError(f"{context}: expected {sorted(expected)!r}")
        parent = _mapping(row["parent"], f"{context}/parent")
        if set(parent) != {"node", "tag"}:
            raise ValueError(f"{context}/parent: expected node and tag")
        resource = UiResourceKey.parse(str(row["view"]))
        parent_id = f"0x{int(str(parent['node']), 0):04x}"
        tag = _fourcc(row["tag"], f"{context}/tag")
        identity = (resource, parent_id, tag)
        if identity in identities:
            raise ValueError(f"{context}: duplicate child {tag!r} under {parent_id}")
        identities.add(identity)
        geometry = _sequence(row["geometry"], 4, f"{context}/geometry")
        family_row = _mapping(row["family"], f"{context}/family")
        evidence = str(row["evidence"]).strip()
        if not evidence:
            raise ValueError(f"{context}: evidence is required")
        patches.append(
            UiChildNodePatch(
                resource=resource,
                parent_id=parent_id,
                parent_tag=_fourcc(parent["tag"], f"{context}/parent/tag"),
                type_code=_fourcc(row["type"], f"{context}/type"),
                tag=tag,
                class_name=str(row["class"]),
                geometry=tuple(int(value) for value in geometry),
                family=_parse_windows_family(family_row, f"{context}/family"),
                evidence=evidence,
            )
        )
    return tuple(patches)


def load_city_building_visuals(repo_root: Path) -> CityBuildingVisuals:
    data = yaml.safe_load((repo_root / WINDOWS_DELTA_PATH).read_text(encoding="utf-8"))
    context = f"{WINDOWS_DELTA_PATH}: city_buildings"
    section = _mapping(data.get("city_buildings"), context)
    if set(section) != {"view", "evidence", "visuals"}:
        raise ValueError(f"{context}: expected view, evidence, and visuals")
    if not str(section["evidence"]).strip():
        raise ValueError(f"{context}: evidence is required")

    rows = _sequence(section["visuals"], 16, f"{context}/visuals")
    visuals: list[CityBuildingVisual] = []
    slots: set[str] = set()
    draw_orders: set[int] = set()
    for index, raw_row in enumerate(rows):
        row_context = f"{context}/visuals[{index}]"
        row = _mapping(raw_row, row_context)
        if set(row) != {"slot", "origin", "draw_order", "dialog"}:
            raise ValueError(f"{row_context}: malformed city building visual")
        slot = str(row["slot"])
        if not slot or slot in slots:
            raise ValueError(f"{row_context}: duplicate or empty slot {slot!r}")
        slots.add(slot)
        origin = _sequence(row["origin"], 2, f"{row_context}/origin")
        draw_order = int(row["draw_order"])
        if not 0 <= draw_order < 16 or draw_order in draw_orders:
            raise ValueError(f"{row_context}: invalid or duplicate draw order {draw_order}")
        draw_orders.add(draw_order)
        visuals.append(
            CityBuildingVisual(
                slot=slot,
                origin=(int(origin[0]), int(origin[1])),
                draw_order=draw_order,
                dialog=UiResourceKey.parse(str(row["dialog"])),
            )
        )
    if draw_orders != set(range(16)):
        raise ValueError(f"{context}: draw order must be exactly 0 through 15")
    expected_slots = (
        "textile_mill",
        "clothing_factory",
        "steel_mill",
        "metalworks",
        "lumber_mill",
        "furniture_factory",
        "oil_refinery",
        "shipyard",
        "armory",
        "trade_school",
        "university",
        "power_plant",
        "food_processing",
        "warehouse",
        "transport",
        "regional_population",
    )
    if tuple(visual.slot for visual in visuals) != expected_slots:
        raise ValueError(f"{context}: slots must follow the production-slot order")
    return CityBuildingVisuals(
        view=UiResourceKey.parse(str(section["view"])),
        visuals=tuple(visuals),
    )


def load_city_building_action_visuals(repo_root: Path) -> CityBuildingActionVisuals:
    data = yaml.safe_load((repo_root / WINDOWS_DELTA_PATH).read_text(encoding="utf-8"))
    context = f"{WINDOWS_DELTA_PATH}: city_building_actions"
    section = _mapping(data.get("city_building_actions"), context)
    if set(section) != {"view", "evidence", "actions"}:
        raise ValueError(f"{context}: expected view, evidence, and actions")
    if not str(section["evidence"]).strip():
        raise ValueError(f"{context}: evidence is required")

    expected_picture_ids = (
        15000,
        15003,
        15004,
        15006,
        15010,
        15013,
        15014,
        15016,
        15017,
        15020,
        15021,
        15023,
        15024,
        15026,
        15027,
        15028,
        15030,
        15031,
        15033,
        15034,
        15036,
        15037,
        15040,
        15041,
        15043,
        15044,
        15045,
        15046,
        15047,
        15050,
        15051,
        15053,
        15056,
        15057,
        15058,
        15060,
        15070,
    )
    slots_by_group = (
        "textile_mill",
        "clothing_factory",
        "steel_mill",
        "metalworks",
        "lumber_mill",
        "furniture_factory",
        "oil_refinery",
        "power_plant",
    )
    rows = _sequence(
        section["actions"], len(expected_picture_ids), f"{context}/actions"
    )
    actions: list[CityBuildingActionVisual] = []
    for index, raw_row in enumerate(rows):
        row_context = f"{context}/actions[{index}]"
        row = _mapping(raw_row, row_context)
        expected_fields = {
            "slot",
            "level",
            "picture_id",
            "frame_count",
            "origin",
            "frame_size",
        }
        if set(row) != expected_fields:
            raise ValueError(f"{row_context}: malformed city building action visual")
        picture_id = int(row["picture_id"])
        if picture_id != expected_picture_ids[index]:
            raise ValueError(
                f"{row_context}: expected recovered picture id {expected_picture_ids[index]}"
            )
        group = (picture_id - 15000) // 10
        level = (picture_id % 10) // 3 + 1
        slot = str(row["slot"])
        if slot != slots_by_group[group] or int(row["level"]) != level:
            raise ValueError(f"{row_context}: slot or level does not match picture id")
        frame_count = int(row["frame_count"])
        if not 0 < frame_count <= 255:
            raise ValueError(f"{row_context}: frame count must fit a nonzero byte")
        origin = _sequence(row["origin"], 2, f"{row_context}/origin")
        frame_size = _sequence(row["frame_size"], 2, f"{row_context}/frame_size")
        origin_pair = (int(origin[0]), int(origin[1]))
        frame_size_pair = (int(frame_size[0]), int(frame_size[1]))
        if min(*origin_pair, *frame_size_pair) < 0 or min(frame_size_pair) == 0:
            raise ValueError(
                f"{row_context}: origin must be nonnegative and frame size positive"
            )
        if (
            origin_pair[0] + frame_size_pair[0] > 640
            or origin_pair[1] + frame_size_pair[1] > 480
        ):
            raise ValueError(f"{row_context}: frame falls outside the retail canvas")
        actions.append(
            CityBuildingActionVisual(
                slot=slot,
                level=level,
                picture_id=picture_id,
                frame_count=frame_count,
                origin=origin_pair,
                frame_size=frame_size_pair,
            )
        )
    return CityBuildingActionVisuals(
        view=UiResourceKey.parse(str(section["view"])),
        actions=tuple(actions),
    )


def _load_row_controls(
    rows: object, length: int, context: str
) -> tuple[CityRowControls, ...]:
    loaded: list[CityRowControls] = []
    for index, raw_row in enumerate(_sequence(rows, length, context)):
        row_context = f"{context}[{index}]"
        row = _mapping(raw_row, row_context)
        if set(row) != {"cluster", "button"}:
            raise ValueError(f"{row_context}: expected cluster and button")
        loaded.append(
            CityRowControls(
                cluster=_fourcc(row["cluster"], f"{row_context}/cluster"),
                button=_fourcc(row["button"], f"{row_context}/button"),
            )
        )
    return tuple(loaded)


def load_city_dialog_controls(repo_root: Path) -> CityDialogControls:
    data = yaml.safe_load((repo_root / WINDOWS_DELTA_PATH).read_text(encoding="utf-8"))
    context = f"{WINDOWS_DELTA_PATH}: city_dialog_controls"
    section = _mapping(data.get("city_dialog_controls"), context)
    expected = {
        "evidence",
        "armory_rows",
        "university_rows",
        "shipyard_rows",
        "shipyard_stat_origins",
        "training_orders",
        "food_order",
        "power_order",
        "transport_order",
        "population_order",
        "warehouse_stocks",
        "industry",
    }
    if set(section) != expected:
        raise ValueError(f"{context}: unexpected keys")
    if not str(section["evidence"]).strip():
        raise ValueError(f"{context}: evidence is required")

    shipyard_rows: list[CityShipyardRowControls] = []
    for index, raw_row in enumerate(
        _sequence(section["shipyard_rows"], 8, f"{context}/shipyard_rows")
    ):
        row_context = f"{context}/shipyard_rows[{index}]"
        row = _mapping(raw_row, row_context)
        if set(row) != {"cluster", "button", "overlay_left"}:
            raise ValueError(f"{row_context}: malformed shipyard row")
        overlay_left = int(row["overlay_left"])
        if overlay_left < 0:
            raise ValueError(f"{row_context}: overlay_left must be non-negative")
        shipyard_rows.append(
            CityShipyardRowControls(
                cluster=_fourcc(row["cluster"], f"{row_context}/cluster"),
                button=_fourcc(row["button"], f"{row_context}/button"),
                overlay_left=overlay_left,
            )
        )

    origins: list[tuple[int, int]] = []
    for index, raw_origin in enumerate(
        _sequence(section["shipyard_stat_origins"], 6, f"{context}/shipyard_stat_origins")
    ):
        origin = _sequence(raw_origin, 2, f"{context}/shipyard_stat_origins[{index}]")
        origins.append((int(origin[0]), int(origin[1])))

    industry_slots = (
        "textile_mill",
        "clothing_factory",
        "steel_mill",
        "metalworks",
        "lumber_mill",
        "furniture_factory",
        "oil_refinery",
    )
    industry: list[CityIndustryPageControls] = []
    for index, raw_page in enumerate(
        _sequence(section["industry"], 7, f"{context}/industry")
    ):
        page_context = f"{context}/industry[{index}]"
        page = _mapping(raw_page, page_context)
        if set(page) != {"slot", "orders", "stocks"}:
            raise ValueError(f"{page_context}: malformed industry page")
        slot = str(page["slot"])
        if slot != industry_slots[index]:
            raise ValueError(f"{page_context}: expected slot {industry_slots[index]}")
        orders = tuple(
            _fourcc(tag, f"{page_context}/orders[{order_index}]")
            for order_index, tag in enumerate(page["orders"])
        )
        if not orders:
            raise ValueError(f"{page_context}: orders must not be empty")
        stocks: list[tuple[str, int]] = []
        raw_stocks = page["stocks"]
        if not isinstance(raw_stocks, list) or not raw_stocks:
            raise ValueError(f"{page_context}/stocks: expected a non-empty list")
        for stock_index, raw_stock in enumerate(raw_stocks):
            stock_context = f"{page_context}/stocks[{stock_index}]"
            stock = _mapping(raw_stock, stock_context)
            if set(stock) != {"tag", "columns"}:
                raise ValueError(f"{stock_context}: expected tag and columns")
            columns = int(stock["columns"])
            if columns not in (1, 2):
                raise ValueError(f"{stock_context}: columns must be 1 or 2")
            stocks.append((_fourcc(stock["tag"], f"{stock_context}/tag"), columns))
        industry.append(
            CityIndustryPageControls(slot, orders, tuple(stocks))
        )

    warehouse = tuple(
        _fourcc(tag, f"{context}/warehouse_stocks[{index}]")
        for index, tag in enumerate(
            _sequence(section["warehouse_stocks"], 20, f"{context}/warehouse_stocks")
        )
    )
    training = tuple(
        _fourcc(tag, f"{context}/training_orders[{index}]")
        for index, tag in enumerate(
            _sequence(section["training_orders"], 2, f"{context}/training_orders")
        )
    )
    return CityDialogControls(
        armory_rows=_load_row_controls(section["armory_rows"], 8, f"{context}/armory_rows"),
        university_rows=_load_row_controls(
            section["university_rows"], 7, f"{context}/university_rows"
        ),
        shipyard_rows=tuple(shipyard_rows),
        shipyard_stat_origins=tuple(origins),
        training_orders=training,
        food_order=_fourcc(section["food_order"], f"{context}/food_order"),
        power_order=_fourcc(section["power_order"], f"{context}/power_order"),
        transport_order=_fourcc(section["transport_order"], f"{context}/transport_order"),
        population_order=_fourcc(
            section["population_order"], f"{context}/population_order"
        ),
        warehouse_stocks=warehouse,
        industry=tuple(industry),
    )


def apply_windows_text_property_patches(
    key: UiResourceKey,
    view: UiSemanticView,
    patches: Iterable[UiTextPropertyPatch],
    text_resources: TextResources,
) -> UiSemanticView:
    scoped = {patch.node_id: patch for patch in patches if patch.resource == key}
    if not scoped:
        return view
    known_nodes = {node.node_id for node in view.nodes}
    unknown = sorted(set(scoped) - known_nodes)
    if unknown:
        raise ValueError(
            f"{WINDOWS_DELTA_PATH}: {key.text()} patches unknown nodes {', '.join(unknown)}"
        )
    nodes: list[UiSemanticNode] = []
    for node in view.nodes:
        patch = scoped.get(node.node_id)
        if patch is None:
            nodes.append(node)
            continue
        if patch.tag != node.tag:
            raise ValueError(
                f"{WINDOWS_DELTA_PATH}: {key.text()} {node.node_id} tag "
                f"{node.tag!r} does not match declared {patch.tag!r}"
            )
        original_text = node.family.text or UiTextPayload(
            resource_id=0,
            resource_index=-1,
            value="",
            source=patch.evidence,
            mode=patch.font_family,
            flags=patch.face_flags,
            point_size=patch.point_size,
            style_ref=0,
            theme=patch.alignment,
        )
        text = replace(
            original_text,
            mode=patch.font_family,
            flags=patch.face_flags,
            point_size=patch.point_size,
            theme=patch.alignment,
            color_index=(
                patch.color_index
                if patch.color_index is not None
                else original_text.color_index
            ),
            shadow_color_index=(
                patch.shadow_color_index
                if patch.shadow_color_index is not None
                else original_text.shadow_color_index
            ),
            shadow_offset=(
                patch.shadow_offset
                if patch.shadow_offset is not None
                else original_text.shadow_offset
            ),
            resource_id=(
                patch.resource_id
                if patch.resource_id is not None
                else original_text.resource_id
            ),
            resource_index=(
                patch.resource_index
                if patch.resource_index is not None
                else original_text.resource_index
            ),
            value=(
                _text_value(
                    text_resources,
                    UiResourceKey(patch.resource_file or key.resource_file, key.view_id),
                    patch.resource_id,
                    patch.resource_index,
                )
                if patch.resource_id is not None and patch.resource_index is not None
                else original_text.value
            ),
            source=patch.evidence if patch.resource_id is not None else original_text.source,
        )
        geometry = node.geometry
        if patch.geometry_top_delta is not None:
            x, y, width, height = geometry
            geometry = (
                x,
                y + patch.geometry_top_delta,
                width,
                height - patch.geometry_top_delta,
            )
        nodes.append(
            replace(
                node,
                geometry=geometry,
                family=replace(node.family, text=text),
                source=f"{node.source}; Windows: {patch.evidence}",
            )
        )
    return replace(view, nodes=tuple(nodes))


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
        optional = {
            "mode",
            "flags",
            "point_size",
            "style_ref",
            "theme",
            "color_index",
            "shadow_color_index",
            "shadow_offset",
            "center_vertically",
        }
        if not required <= set(text) or set(text) - (required | optional):
            raise ValueError(f"{context}/text: malformed semantic text binding")
        if "shadow_offset" in text:
            _sequence(text["shadow_offset"], 2, f"{context}/text/shadow_offset")
        if ("shadow_color_index" in text) != ("shadow_offset" in text):
            raise ValueError(
                f"{context}/text: shadow_color_index and shadow_offset "
                "must be declared together"
            )
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
            color_index=(
                int(text_row["color_index"])
                if "color_index" in text_row
                else None
            ),
            shadow_color_index=(
                int(text_row["shadow_color_index"])
                if "shadow_color_index" in text_row
                else None
            ),
            shadow_offset=tuple(
                int(value) for value in text_row.get("shadow_offset", (0, 0))
            ),
            center_vertically=bool(text_row.get("center_vertically", False)),
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
    unexpected = sorted(set(data) - {"views"})
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
                    source=f"Windows evidence at 0x{node_evidence:08x}",
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


def _normalize_mac_window_payload(type_code: str, raw_family: dict) -> UiWindowPayload:
    # The Mac `fwnd` window-flags word is also the Windows TWindow style type for
    # the 0x1f40 floating-window family. The retail Windows factory at 0x0041b6d0
    # emits this exact descriptor for the city building dialogs: flags 0x80,
    # style 0x1f40, topmost/resource 6f/6e/captioned-frame/resource 71 set, and
    # resource 6c clear. Keep the generic fallback for Mac window encodings whose
    # Windows translation has not yet been corroborated.
    raw_window_flags = raw_family.get("window_flags")
    if type_code == "fwnd" and raw_window_flags == 0x1F40:
        return UiWindowPayload(
            0x80,
            0x1F40,
            1,
            1,
            1,
            1,
            0,
            1,
            UiWindowColorPayload(1, 1, 0x20202020, 0x20202020),
        )
    return UiWindowPayload(
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
            window = _normalize_mac_window_payload(type_code, raw_family)
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
    nodes: list[UiSemanticNode] = []
    for node in view.nodes:
        override = overrides.get(node.node_id)
        if override is None:
            nodes.append(node)
            continue
        family = node.family
        if override.content_insets is not None:
            if family.content_insets is None:
                raise ValueError(
                    f"{MANIFEST_PATH}: 0x{recipe.address:08x}/0x{case.event:x}/"
                    f"{node.node_id} overrides missing content insets"
                )
            family = replace(family, content_insets=override.content_insets)
        if override.style_word is not None and override.packed_color is not None:
            family = replace(
                family,
                style=UiStylePayload(override.style_word, override.packed_color),
            )
        if override.text_source is not None:
            if family.text is None:
                raise ValueError(
                    f"{MANIFEST_PATH}: 0x{recipe.address:08x}/0x{case.event:x}/"
                    f"{node.node_id} overrides missing text"
                )
            family = replace(
                family,
                text=replace(family.text, value=None, source=override.text_source),
            )
        nodes.append(
            replace(
                node,
                enabled=(override.enabled if override.enabled is not None else node.enabled),
                control_value=(
                    override.control_value
                    if override.control_value is not None
                    else node.control_value
                ),
                family=family,
                source=f"{node.source}; Windows: {override.evidence}",
            )
        )
    return replace(view, nodes=tuple(nodes))


def _rust_amount_bar_kind(node: UiSemanticNode) -> str | None:
    """Map recovered TAmtBar subclasses to RetailAmountBarKind variants."""
    return {
        "TIndustryAmtBar": "Industry",
        "TRailAmtBar": "Rail",
        "TTraderAmtBar": "Trader",
    }.get(node.class_name)


def _rust_amount_selector_kind(node: UiSemanticNode) -> str | None:
    return {
        "TIndustryCluster": "Industry",
        "TRailCluster": "Rail",
        "TTradeCluster": "Trader",
    }.get(node.class_name)


def _rust_amount_selector_child_name(tag: str) -> str | None:
    return {
        "left": "Left",
        "rght": "Right",
        "move": "Value",
        "Sell": "Value",
        "bar ": "Bar",
    }.get(tag)


def _rust_two_pic_slider(node: UiSemanticNode) -> tuple[int, int, int, int] | None:
    """Windows DoPostCreate picture base + scale + Off string for TTwoPicSlider."""

    if node.class_name != "TTwoPicSlider":
        return None
    # (picture_base, scale, string_group, direct_string_index)
    return {
        "musi": (0x1036, 0xFF, 0x2743, 0x3C),
        "soun": (0x1038, 100, 0x2743, 0x3C),
    }.get(node.tag)


def _rust_widget_kind(node: UiSemanticNode) -> str:
    class_name = node.class_name.casefold()
    if node.type_code == "wind":
        return "window"
    if node.type_code == "fwnd":
        return "floating_window"
    if node.type_code == "chkb" or "czechbox" in class_name or "checkbox" in class_name:
        return "checkbox"
    if node.type_code == "radb" or "radio" in class_name:
        return "radio_or_cluster_control"
    if node.class_name == "TPlacard":
        return "placard"
    if node.class_name == "TArmyPlacard":
        return "army_placard"
    if node.class_name == "TShipPlacard":
        return "ship_placard"
    if node.class_name == "TTransportPicture":
        return "transport_gauge"
    if node.class_name == "TNumberedArrowButton":
        return "numbered_arrow"
    if node.class_name == "TTwoPicSlider":
        return "two_pic_slider"
    if node.class_name == "TScrollView":
        return "scroll_view"
    if node.class_name == "TInfoBarText":
        return "hover_help_bar"
    if _rust_amount_selector_kind(node) is not None:
        return "amount_selector"
    if _rust_amount_bar_kind(node) is not None:
        return "amount_bar"
    if node.type_code == "pict":
        if "toggle" in class_name:
            return "toggle"
        if "button" in class_name:
            return "picture_button"
        return "picture"
    if node.type_code == "stat":
        return "static_text"
    if node.type_code == "nmbr":
        return "numeric_value"
    if node.type_code == "edit":
        return "edit_control"
    if node.type_code == "tevw":
        return "list_or_scrolling_pane"
    if node.type_code == "clus":
        return "radio_or_cluster_control"
    if node.type_code == "view":
        return "container" if node.class_name == "TView" else "custom_canvas"
    return "specialized"


def _rust_widget_behavior(key: UiResourceKey, node: UiSemanticNode) -> str:
    """Return interaction behavior independent from visual [`_rust_widget_kind`].

    The generator is the one place where recovered type/class evidence decides
    whether a static-text-looking control is a radio, a picture is an activate
    button, or a canvas takes pointer input. The generated BSN carries the
    resulting native Bevy component, not those C++ class details.
    """

    class_name = node.class_name.casefold()
    kind = _rust_widget_kind(node)
    # Generic `clus` records are layout groups (TIndustryCluster, TToolBarCluster,
    # the random-setup `stuf` panel). Only TRadioTextCluster is a mutually
    # exclusive option group.
    if node.class_name == "TRadioTextCluster":
        return "radio_group"
    if node.type_code == "radb" or "radio" in class_name:
        return "radio_button"
    # TMadnessButton is a TCzechBox pictured as `pict`; input is Checkbox, not Button.
    if node.class_name == "TMadnessButton":
        return "checkbox"
    if node.type_code == "chkb" or "czechbox" in class_name or "checkbox" in class_name:
        return "checkbox"
    if kind == "toggle":
        return "toggle"
    if node.type_code == "edit":
        return "text_edit"
    if node.class_name == "TTwoPicSlider":
        return "slider"
    if node.class_name == "TScrollView":
        return "scroll_area"
    # TInfoBarText is tevw but not a scroll area; hover-help presentation only.
    if node.class_name == "TInfoBarText":
        return "passive"
    if node.type_code == "tevw":
        return "scroll_area"
    if node.class_name in ("TMapPreviewView", "TCitySiteView", "TCityProductionView"):
        return "pointer_canvas"
    # SceneComponent owns two stock Buttons; recovered root is not itself a Button.
    if node.class_name == "TNumberedArrowButton":
        return "passive"
    if (
        node.type_code in ("cntl", "nmbr")
        or node.class_name == "TSidewaysArrow"
        or (node.type_code == "pict" and "button" in class_name)
        # TSetupRandomMapPicture::DoEvent handles this otherwise passive
        # TNoHilitePicture as the random-map regeneration action.
        or (key == UiResourceKey("Startup.rsrc", 1501) and node.tag == "glob")
    ) and node.class_name != "TTwoPicSlider":
        return "activate"
    return "passive"


def _rust_picture_visual(node: UiSemanticNode) -> str:
    """How retail picture art reacts to Pressed / Checked / disabled.

    Evidence:
    - TUpDownPictureButton / TRadioPictureButton / TTextPictureButton:
      HiliteState swaps to glyphBase84 +/- 1 (immutable resting ID + 1 when active).
    - TCzechBox: CheckTheLook uses odd ID when checked or pressed, even when idle.
    - TMadnessButton: CheckTheLook selects base+{0..4} from checked/pressed/disabled.
    - TPictureButton: HiliteState shows/hides the picture (pressed overlay), not an ID swap.
    """

    class_name = node.class_name
    folded = class_name.casefold()
    if class_name == "TMadnessButton":
        return "madness"
    if class_name == "TPictureButton":
        return "pressed_overlay"
    if node.type_code == "chkb" or "czechbox" in folded:
        return "czech_box"
    if (
        node.type_code == "radb"
        or class_name
        in (
            "TUpDownPictureButton",
            "TRadioPictureButton",
            "TTextPictureButton",
            "TSidewaysArrow",
            "TCivilianButton",
            "TOverlayRadioButton",
        )
        or "updownpicture" in folded
        or "radiopicture" in folded
    ):
        return "up_down"
    return "static"


def _case_for_resource(
    recipes: Iterable[UiFactoryRecipe], key: UiResourceKey
) -> tuple[UiFactoryRecipe, UiCaseRecipe]:
    matches = [
        (recipe, case)
        for recipe in recipes
        for case in recipe.cases
        if case.resource == key
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{key.text()}: expected one factory case, found {len(matches)}"
        )
    return matches[0]


def resource_backed_scene_keys(
    recipes: Iterable[UiFactoryRecipe],
) -> list[UiResourceKey]:
    """Every factory case backed by a committed Mac resource."""

    keys = {
        case.resource
        for recipe in recipes
        for case in recipe.cases
        if case.resource is not None
    }
    return sorted(keys, key=lambda item: (item.resource_file, item.view_id))


def apply_windows_child_node_patches(
    key: UiResourceKey,
    semantic_view: UiSemanticView,
    patches: Iterable[UiChildNodePatch],
) -> UiSemanticView:
    scoped = [patch for patch in patches if patch.resource == key]
    if not scoped:
        return semantic_view
    nodes_by_id = {node.node_id: node for node in semantic_view.nodes}
    additions: dict[str, list[UiSemanticNode]] = {}
    for patch in scoped:
        parent = nodes_by_id.get(patch.parent_id)
        if parent is None or parent.tag != patch.parent_tag:
            raise ValueError(
                f"{WINDOWS_DELTA_PATH}: {key.text()} has no "
                f"{patch.parent_tag} parent at {patch.parent_id}"
            )
        node_id = f"windows:{patch.parent_id}:{patch.tag}"
        if node_id in nodes_by_id:
            raise ValueError(
                f"{WINDOWS_DELTA_PATH}: {key.text()} duplicate semantic node {node_id}"
            )
        child = UiSemanticNode(
            node_id=node_id,
            type_code=patch.type_code,
            tag=patch.tag,
            class_name=patch.class_name,
            parent_id=patch.parent_id,
            geometry=patch.geometry,
            state=1,
            enabled=1,
            input_gate=1,
            child_hit_test=1,
            control_value=0,
            family=patch.family,
            source=f"Windows: {patch.evidence}",
            confidence="high",
        )
        nodes_by_id[node_id] = child
        additions.setdefault(patch.parent_id, []).append(child)

    nodes: list[UiSemanticNode] = []
    for node in semantic_view.nodes:
        nodes.append(node)
        nodes.extend(additions.get(node.node_id, ()))
    return replace(semantic_view, nodes=tuple(nodes))


def _rust_ui_semantic_views(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
) -> tuple[
    list[tuple[UiResourceKey | str, UiSemanticView]],
    CityBuildingVisuals,
    CityBuildingActionVisuals,
]:
    recipe_list = list(recipes)
    text_property_patches = load_windows_text_property_patches(repo_root)
    child_node_patches = load_windows_child_node_patches(repo_root)
    city_buildings = load_city_building_visuals(repo_root)
    city_building_actions = load_city_building_action_visuals(repo_root)
    scene_keys = set(resource_backed_scene_keys(recipe_list))
    unknown_child_views = sorted(
        {patch.resource for patch in child_node_patches} - scene_keys,
        key=lambda item: (item.resource_file, item.view_id),
    )
    if unknown_child_views:
        raise ValueError(
            f"{WINDOWS_DELTA_PATH}: child-node views are not in the native Rust UI: "
            + ", ".join(key.text() for key in unknown_child_views)
        )
    if city_buildings.view not in scene_keys:
        raise ValueError(
            f"{WINDOWS_DELTA_PATH}: city building view "
            f"{city_buildings.view.text()} is not in the native Rust UI"
        )
    if city_building_actions.view != city_buildings.view:
        raise ValueError(
            f"{WINDOWS_DELTA_PATH}: city building actions must belong to "
            f"{city_buildings.view.text()}"
        )
    for visual in city_buildings.visuals:
        if visual.dialog not in scene_keys:
            raise ValueError(
                f"{WINDOWS_DELTA_PATH}: city building dialog "
                f"{visual.dialog.text()} is not in the native Rust UI"
            )
    for index, visual in enumerate(city_buildings.visuals):
        expected_dialogs = [
            key for key in scene_keys if key.view_id == 9200 + index
        ]
        if len(expected_dialogs) != 1 or visual.dialog != expected_dialogs[0]:
            raise ValueError(
                f"{WINDOWS_DELTA_PATH}: city building {visual.slot} dialog "
                "does not match the recovered factory case"
            )
    scene_views: list[tuple[UiResourceKey | str, UiSemanticView]] = []
    for key in sorted(scene_keys, key=lambda item: (item.resource_file, item.view_id)):
        raw_view = views.get(key)
        if raw_view is None:
            raise ValueError(f"{key.text()}: missing committed Mac View IR")
        recipe, case = _case_for_resource(recipe_list, key)
        semantic_view = normalize_resource_view(key, raw_view, text_resources)
        semantic_view = apply_case_windows_overrides(recipe, case, semantic_view)
        semantic_view = apply_windows_text_property_patches(
            key, semantic_view, text_property_patches, text_resources
        )
        semantic_view = apply_windows_child_node_patches(
            key, semantic_view, child_node_patches
        )
        scene_views.append((key, semantic_view))
    windows_views = load_windows_views(repo_root)
    emitted_windows: set[str] = set()
    for recipe in recipe_list:
        for case in recipe.cases:
            if case.windows_view is None or case.windows_view in emitted_windows:
                continue
            semantic_view = windows_views.get(case.windows_view)
            if semantic_view is None:
                raise ValueError(
                    f"{WINDOWS_VIEW_PATH}: missing Windows view {case.windows_view!r}"
                )
            scene_views.append((case.windows_view, semantic_view))
            emitted_windows.add(case.windows_view)
    return scene_views, city_buildings, city_building_actions


def report_unsupported_ui_roles(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
) -> list[str]:
    """On-demand report of specialized visuals and deferred behaviors by view."""

    recipe_list = list(recipes)
    text_property_patches = load_windows_text_property_patches(repo_root)
    lines: list[str] = []
    for key in resource_backed_scene_keys(recipe_list):
        raw_view = views.get(key)
        if raw_view is None:
            lines.append(f"{key.text()}: missing Mac View IR")
            continue
        recipe, case = _case_for_resource(recipe_list, key)
        semantic_view = normalize_resource_view(key, raw_view, text_resources)
        semantic_view = apply_case_windows_overrides(recipe, case, semantic_view)
        semantic_view = apply_windows_text_property_patches(
            key, semantic_view, text_property_patches
        )
        unsupported: list[str] = []
        for node in semantic_view.nodes:
            kind = _rust_widget_kind(node)
            behavior = _rust_widget_behavior(key, node)
            notes: list[str] = []
            if kind == "specialized":
                notes.append(f"kind={kind}")
            if behavior in ("scroll_area",):
                notes.append(f"behavior={behavior}")
            if notes:
                unsupported.append(
                    f"  {node.tag!r} ({node.class_name}): " + ", ".join(notes)
                )
        if unsupported:
            lines.append(f"{key.text()} event=0x{case.event:04x}")
            lines.extend(unsupported)
    return lines


def _rust_string(value: str) -> str:
    rendered = json.dumps(value, ensure_ascii=False)
    return re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: f"\\u{{{match.group(1)}}}",
        rendered,
    )


def _rust_function_name(resource_file: str, resource_id: int) -> str:
    stem = resource_file.removesuffix(".rsrc").casefold()
    stem = re.sub(r"[^a-z0-9]+", "_", stem).strip("_")
    return f"{stem}_{resource_id}"


def _rust_fourcc(tag: str) -> str:
    return f'fourcc!("{tag}")'


def _rust_enum_variant(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))


def _rust_has_shipped_font(text: UiTextPayload) -> bool:
    # 0 = system face; 1..=3 = Belwe / Book Antiqua (see resolve_retail_text_style).
    return text.mode in (0, 1, 2, 3)


def _rust_window_is_captioned(node: UiSemanticNode) -> bool:
    window = node.family.window
    if window is None:
        return False
    descriptor = (
        window.flags,
        window.style_type,
        window.topmost,
        window.resource_6f,
        window.resource_6e,
        window.captioned_frame,
        window.resource_6c,
        window.resource_71,
    )
    styles = {
        (8, 2, 0, 1, 1, 0, 0, 1): False,
        (0x80, 0x1F40, 1, 1, 1, 0, 0, 1): False,
        (0x80, 0x1F40, 1, 1, 1, 1, 0, 1): True,
    }
    try:
        return styles[descriptor]
    except KeyError as exc:
        raise ValueError(
            f"{node.tag}: unsupported recovered window descriptor {descriptor}"
        ) from exc


def _indent(lines: Iterable[str], spaces: int) -> list[str]:
    prefix = " " * spaces
    return [prefix + line if line else "" for line in lines]


def _render_bsn_node(
    key: UiResourceKey | None,
    node: UiSemanticNode,
    children_by_parent: dict[str | None, list[UiSemanticNode]],
) -> list[str]:
    x, y, width, height = node.geometry
    insets = node.family.content_insets or (0, 0, 0, 0)
    text = node.family.text
    render_text_style = text is not None and _rust_has_shipped_font(text)
    lines = [
        "(",
        (
            f"    retail_node(fourcc!({_rust_string(node.tag)}), "
            f"{x}, {y}, {width}, {height})"
        ),
    ]
    if _rust_window_is_captioned(node):
        lines.append("    template(|_context| Ok(CaptionedWindow))")
    if any(int(value) for value in insets):
        lines.extend(
            [
                "    Node {",
                "        padding: UiRect {",
                f"            left: px({int(insets[0])}),",
                f"            top: px({int(insets[1])}),",
                f"            right: px({int(insets[2])}),",
                f"            bottom: px({int(insets[3])}),",
                "        },",
                "    }",
            ]
        )
    behavior = _rust_widget_behavior(key, node)
    lines.extend(
        {
            "activate": ["    Button"],
            "checkbox": ["    Checkbox"],
            "toggle": ["    Checkbox"],
            "radio_group": ["    RadioGroup"],
            "radio_button": ["    RadioButton"],
            "pointer_canvas": ["    RelativeCursorPosition"],
            "scroll_area": [
                "    ScrollArea",
                "    ScrollPosition::default()",
                "    Node {",
                "        overflow: Overflow::scroll_y(),",
                "    }",
                "    Pickable",
            ],
        }.get(str(behavior), [])
    )
    if bool(node.state) and behavior in ("checkbox", "toggle", "radio_button"):
        lines.append("    Checked")
    if behavior != "passive" and (not node.enabled or not node.input_gate):
        lines.append("    InteractionDisabled")

    if node.class_name == "TInfoBarText":
        lines.append("    template(|_context| Ok(HoverHelpBar))")
        # Empty text until hover systems write; style comes from Windows deltas.
        if text is None:
            lines.append('    Text("")')
        # Vertically center the help caption inside the recovered info-bar bounds.
        lines.extend(
            [
                "    Node {",
                "        flex_direction: FlexDirection::Column,",
                "        justify_content: JustifyContent::Center,",
                "        overflow: Overflow::clip(),",
                "    }",
            ]
        )

    if text is not None:
        value = _rust_string(text.value or "")
        if behavior == "text_edit":
            max_chars = node.family.max_chars
            if max_chars is not None and max_chars < 0:
                max_chars = None
            max_expr = "None" if max_chars is None else f"Some({max_chars})"
            lines.append("    retail_edit_field()")
            lines.append(f"    retail_editable_text({value}, {max_expr})")
        else:
            lines.append(f"    Text({value})")
        if render_text_style:
            lines.append(
                "    retail_text_style("
                f"{text.mode}, {text.flags}, {text.point_size}, {text.theme})"
            )
        if text.color_index is None:
            lines.append("    TextColor(Color::BLACK)")
        else:
            lines.append(f"    retail_text_color({text.color_index})")
        if text.shadow_color_index is not None:
            lines.append(
                f"    retail_text_shadow({text.shadow_color_index}, "
                f"{text.shadow_offset[0]}, {text.shadow_offset[1]})"
            )
        if render_text_style and text.center_vertically:
            lines.append(
                "    retail_centered_text_padding("
                f"{text.mode}, {text.flags}, {text.point_size}, "
                f"{height}, {insets[1]})"
            )

    picture_id = node.family.picture_id
    if picture_id is not None:
        visual = _rust_picture_visual(node)
        idle_id = int(picture_id)
        active_id = idle_id
        if visual == "up_down":
            active_id += 1
        elif visual == "czech_box":
            idle_id &= ~1
            active_id = int(picture_id) | 1
        if node.class_name == "TPlacard":
            # Recovered class -> RetailPlacard widget (picture + value presentation).
            lines.append(f"    retail_placard({idle_id})")
        elif node.class_name == "TArmyPlacard":
            lines.append(f"    retail_army_placard({idle_id})")
        elif node.class_name == "TShipPlacard":
            lines.append(f"    retail_ship_placard({idle_id})")
        elif node.class_name == "TTransportPicture":
            # track_left mirrors Refresh: ownerLocalX > 0xc8 => 0x5d else 0x61.
            track_left = 0x5D if int(node.geometry[0]) > 0xC8 else 0x61
            kind = "Capacity" if node.tag == "tota" else "Allocation"
            lines.append(
                "    retail_transport_gauge("
                f"{idle_id}, RetailTransportGaugeKind::{kind}, {track_left})"
            )
        elif visual == "pressed_overlay":
            lines.append(f"    retail_pressed_overlay_picture({idle_id})")
        elif visual == "madness":
            lines.append(f"    retail_madness_picture({idle_id})")
        elif visual == "static":
            lines.append(f"    retail_picture({idle_id})")
        else:
            lines.append(f"    retail_picture_swap({idle_id}, {active_id})")
    elif node.class_name == "TNumberedArrowButton":
        lines.append("    retail_numbered_arrow()")
    elif behavior == "radio_button":
        # TRadioText has no picture; Draw fills the selected/pressed option.
        lines.append("    retail_radio_text_fill()")

    amount_bar_kind = _rust_amount_bar_kind(node)
    if amount_bar_kind is not None:
        # Recovered TAmtBar subclass -> RetailAmountBar widget.
        lines.append(
            f"    retail_amount_bar(RetailAmountBarKind::{amount_bar_kind})"
        )

    selector_kind = _rust_amount_selector_kind(node)
    if selector_kind is not None:
        lines.append(
            f"    retail_amount_selector(RetailAmountSelectorKind::{selector_kind})"
        )

    slider = _rust_two_pic_slider(node)
    if slider is not None:
        picture_base, scale, off_group, off_index = slider
        lines.append(
            "    retail_two_pic_slider("
            f"{picture_base}, {scale}, {off_group}, {off_index})"
        )

    children = children_by_parent.get(node.node_id, [])
    if children:
        lines.append("    Children [")
        for child in children:
            rendered = _render_bsn_node(key, child, children_by_parent)
            child_name = (
                _rust_amount_selector_child_name(child.tag)
                if selector_kind is not None
                else None
            )
            if child_name is not None:
                # Name recovered cluster children for RetailAmountSelector refs.
                rendered.insert(1, f"    #{child_name}")
            rendered[-1] += ","
            lines.extend(_indent(rendered, 8))
        lines.append("    ]")
    lines.append(")")
    return lines


def _render_city_dialog_controls(
    city_buildings: CityBuildingVisuals,
    controls: CityDialogControls,
) -> list[str]:
    def row_array(name: str, rows: tuple[CityRowControls, ...]) -> list[str]:
        lines = [f"pub const {name}: [(FourCc, FourCc); {len(rows)}] = ["]
        for row in rows:
            lines.append(
                f"    ({_rust_fourcc(row.cluster)}, {_rust_fourcc(row.button)}),"
            )
        lines.extend(["];", ""])
        return lines

    lines: list[str] = []
    lines.extend(row_array("ARMORY_ROW_CONTROLS", controls.armory_rows))
    lines.extend(row_array("UNIVERSITY_ROW_CONTROLS", controls.university_rows))
    lines.append(
        f"pub const SHIPYARD_ROW_CONTROLS: [(FourCc, FourCc, i32); {len(controls.shipyard_rows)}] = ["
    )
    for row in controls.shipyard_rows:
        lines.append(
            f"    ({_rust_fourcc(row.cluster)}, {_rust_fourcc(row.button)}, {row.overlay_left}),"
        )
    lines.extend(["];", ""])
    lines.append(
        f"pub const SHIPYARD_STAT_ORIGINS: [(i32, i32); {len(controls.shipyard_stat_origins)}] = ["
    )
    for left, top in controls.shipyard_stat_origins:
        lines.append(f"    ({left}, {top}),")
    lines.extend(["];", ""])
    training = ", ".join(_rust_fourcc(tag) for tag in controls.training_orders)
    lines.append(f"pub const TRAINING_ORDER_TAGS: [FourCc; 2] = [{training}];")
    lines.append(f"pub const FOOD_ORDER_TAG: FourCc = {_rust_fourcc(controls.food_order)};")
    lines.append(f"pub const POWER_ORDER_TAG: FourCc = {_rust_fourcc(controls.power_order)};")
    lines.append(
        f"pub const TRANSPORT_ORDER_TAG: FourCc = {_rust_fourcc(controls.transport_order)};"
    )
    lines.append(
        f"pub const POPULATION_ORDER_TAG: FourCc = {_rust_fourcc(controls.population_order)};"
    )
    lines.extend(
        [
            "pub const WAREHOUSE_STOCK_TAGS: [FourCc; 20] = [",
        ]
    )
    for tag in controls.warehouse_stocks:
        lines.append(f"    {_rust_fourcc(tag)},")
    lines.extend(
        [
            "];",
            "",
            "pub struct IndustryPageControls {",
            "    pub slot: CityFacilitySlot,",
            "    pub order_tags: &'static [FourCc],",
            "    pub stocks: &'static [(FourCc, i16)],",
            "}",
            "",
            "pub const INDUSTRY_PAGE_CONTROLS: [IndustryPageControls; 7] = [",
        ]
    )
    for page in controls.industry:
        order_tags = ", ".join(_rust_fourcc(tag) for tag in page.order_tags)
        stocks = ", ".join(
            f"({_rust_fourcc(tag)}, {columns})" for tag, columns in page.stocks
        )
        lines.extend(
            [
                "    IndustryPageControls {",
                f"        slot: CityFacilitySlot::{_rust_enum_variant(page.slot)},",
                f"        order_tags: &[{order_tags}],",
                f"        stocks: &[{stocks}],",
                "    },",
            ]
        )
    lines.extend(["];", ""])
    lines.append("pub fn spawn_city_dialog(commands: &mut Commands, slot: CityFacilitySlot) -> Entity {")
    lines.append("    match slot {")
    for visual in city_buildings.visuals:
        function = _rust_function_name(visual.dialog.resource_file, visual.dialog.view_id)
        variant = _rust_enum_variant(visual.slot)
        lines.append(
            f"        CityFacilitySlot::{variant} => commands.spawn_scene({function}()).id(),"
        )
    lines.extend(["    }", "}"])
    return lines


def render_rust_ui(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
) -> str:
    scene_views, city_buildings, city_building_actions = _rust_ui_semantic_views(
        repo_root, recipes, views, text_resources
    )
    dialog_controls = load_city_dialog_controls(repo_root)
    lines = [
        "// @generated by tools.ui_codegen. Do not edit by hand.",
        "#![allow(dead_code, clippy::identity_op)]",
        "",
        "use super::city::{CityBuildingActionVisual, CityBuildingVisual};",
        "use super::hover_help::HoverHelpBar;",
        "use super::retail::*;",
        "use super::window::CaptionedWindow;",
        "use bevy::prelude::*;",
        "use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition, ScrollPosition};",
        "use bevy::ui_widgets::{Button, Checkbox, RadioButton, RadioGroup, ScrollArea};",
        "use imperialism_core::CityFacilitySlot;",
        "use imperialism_formats::{FourCc, PictureId, fourcc};",
        "",
        "pub const LOGICAL_RESOLUTION: [u32; 2] = [640, 480];",
        "",
    ]
    lines.extend(["pub const CITY_BUILDINGS: &[CityBuildingVisual] = &["])
    for visual in city_buildings.visuals:
        lines.extend(
            [
                "    CityBuildingVisual {",
                f"        slot: CityFacilitySlot::{_rust_enum_variant(visual.slot)},",
                f"        origin: [{visual.origin[0]}, {visual.origin[1]}],",
                f"        draw_order: {visual.draw_order},",
                "    },",
            ]
        )
    lines.extend(["];", "", "pub const CITY_BUILDING_ACTIONS: &[CityBuildingActionVisual] = &["])
    for action in city_building_actions.actions:
        lines.extend(
            [
                "    CityBuildingActionVisual {",
                f"        slot: CityFacilitySlot::{_rust_enum_variant(action.slot)},",
                f"        level: {action.level},",
                f"        picture_id: PictureId::new({action.picture_id}),",
                f"        frame_count: {action.frame_count},",
                f"        origin: [{action.origin[0]}, {action.origin[1]}],",
                f"        frame_size: [{action.frame_size[0]}, {action.frame_size[1]}],",
                "    },",
            ]
        )
    lines.extend(["];", ""])
    lines.extend(_render_city_dialog_controls(city_buildings, dialog_controls))
    lines.append("")
    for view_id, semantic_view in scene_views:
        if isinstance(view_id, UiResourceKey):
            function = _rust_function_name(view_id.resource_file, view_id.view_id)
            view_name = _rust_string(view_id.text())
            key = view_id
        else:
            function = view_id
            view_name = _rust_string(function)
            key = None
        children_by_parent: dict[str | None, list[UiSemanticNode]] = {}
        for node in semantic_view.nodes:
            children_by_parent.setdefault(node.parent_id, []).append(node)
        roots = children_by_parent.get(None, [])
        if len(roots) != 1:
            raise ValueError(f"{semantic_view.view_id}: expected one semantic root")
        lines.extend(
            [
                "#[rustfmt::skip]",
                f"pub fn {function}() -> impl Scene {{",
                "    bsn! {",
                f"        retail_view({view_name})",
                "        Children [",
            ]
        )
        for node in roots:
            rendered = _render_bsn_node(key, node, children_by_parent)
            rendered[-1] += ","
            lines.extend(_indent(rendered, 12))
        lines.extend(["        ]", "    }", "}", ""])
    return "\n".join(lines)


def write_rust_ui(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
) -> Path:
    path = repo_root / RUST_UI_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_if_changed(
        path, render_rust_ui(repo_root, recipes, views, text_resources)
    )
    return path


def rust_ui_is_current(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    text_resources: TextResources,
) -> bool:
    path = repo_root / RUST_UI_PATH
    return path.is_file() and path.read_text(encoding="utf-8") == render_rust_ui(
        repo_root, recipes, views, text_resources
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
    if not value:
        return "g_szEmptyString"

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
                "  if (static_cast<short>(nEventCode) != "
                f"{vocabulary_by_event[recipe.cases[0].event]}) {{",
                "    return 0;",
                "  }",
            )
        )
    else:
        body.append("  switch (static_cast<short>(nEventCode)) {")
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
            "      static_cast<short>(nEventCode), g_pUiResourceHead);",
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
        {"functions": source_maps},
        indent=2,
        sort_keys=True,
    ) + "\n"
    _write_if_changed(output_dir / "_source_map.json", source_map_text)
    manifest = {
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
    parser.add_argument(
        "--write-rust-ui",
        action="store_true",
        help=f"write native Bevy UI scenes to {RUST_UI_PATH}",
    )
    parser.add_argument(
        "--report-unsupported-roles",
        action="store_true",
        help="print specialized visuals and deferred behaviors by model view",
    )
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
        print(f"{event}: nodes={len(nodes)} {counts}; {case['source']}")


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
    if args.write_rust_ui:
        path = write_rust_ui(
            repo_root, recipes, views, text_resources
        )
        print(f"Wrote native Bevy UI scenes to {path}")
        return 0
    if args.report_unsupported_roles:
        for line in report_unsupported_ui_roles(
            repo_root, recipes, views, text_resources
        ):
            print(line)
        return 0
    selected = recipes
    if args.function:
        address = int(args.function, 0)
        selected = [recipe for recipe in recipes if recipe.address == address]
        if not selected:
            raise SystemExit(f"No UI factory at 0x{address:08x}")
    if args.check:
        if not rust_ui_is_current(
            repo_root, recipes, views, text_resources
        ):
            print(
                f"UI codegen check failed: {RUST_UI_PATH} is stale; "
                "run with --write-rust-ui"
            )
            return 1
        scene_count = len(
            {
                case.resource if case.resource is not None else case.windows_view
                for recipe in recipes
                for case in recipe.cases
                if case.resource is not None or case.windows_view is not None
            }
        )
        print(
            f"UI codegen check passed: {len(recipes)} functions, "
            f"{sum(len(recipe.cases) for recipe in recipes)} cases, "
            f"{scene_count} native Bevy scenes"
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
