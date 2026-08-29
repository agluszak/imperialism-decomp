#!/usr/bin/env python3
"""Generate native Rust BSN UI scenes from committed retail evidence."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tools.common.repo import repo_root_from_file, resolve_repo_path

MANIFEST = "config/ui_factory_codegen.yml"
IR_PATH = "vendor/macos_codewarrior/evidence/resources/ui_views.json"
STRINGS_PATH = "vendor/macos_codewarrior/evidence/resources/strings.csv"
TEXT_RESOURCES_PATH = "vendor/macos_codewarrior/evidence/resources/text_resources.json"
WINDOWS_VIEWS_PATH = "config/ui_factory_windows_views.yml"
DELTAS_PATH = "config/ui_platform_deltas.yml"
RUST_OUT = "../rust/crates/imperialism-app/src/ui/generated.rs"
RUST_CITY_LAYOUT_OUT = (
    "../rust/crates/imperialism-app/src/ui/city/building_layout_generated.rs"
)

DEFAULT_CLASSES = {
    "view": "TView", "pict": "TPicture", "cntl": "TControl", "stat": "TStaticText",
    "clus": "TCluster", "tevw": "TTEView", "edit": "TEditText", "nmbr": "TNumberText",
    "radb": "TRadioPictureButton", "chkb": "TCzechBox", "wind": "TWindow", "fwnd": "TFloatWindow",
}
LAYOUT_TYPES = frozenset(("pict", "cntl", "stat", "clus", "edit", "nmbr", "radb", "chkb"))
CONTAINER_TYPES = frozenset(("view", "clus", "tevw", "wind", "fwnd"))
TEXT_TYPES = frozenset(("stat", "nmbr", "edit"))
MAC_FONTS = {"": 0, "a": 3, "chicago": 0, "geneva": 3, "helvetica": 21, "palatino": 16}
ATOMIC_CLASSES = frozenset(
    ("TPlacard", "TArmyPlacard", "TShipPlacard", "TNumberedArrowButton",
     "TIndustryAmtBar", "TRailAmtBar", "TTraderAmtBar", "TTwoPicSlider")
)
CHECKBOX_CLASSES = frozenset(("TCzechBox", "TToggleButton", "TMadnessButton"))
RADIO_CLASSES = frozenset(("TRadioPictureButton", "TOverlayRadioButton", "TCivilianButton", "TRadioText"))
BUTTON_CLASSES = frozenset(
    ("T2PictureButton", "TClickZone", "TControl", "TDealTabControl", "TNoHilitePicture",
     "TPictureNumberText", "TTextPictureButton", "TUpDownPictureButton", "TPictureButton")
)
PICTURE_OVERLAY_CLASSES = frozenset(("TPictureButton",))
CHECKBOX_SWAP_CLASSES = frozenset(("TCzechBox",))


@dataclass(frozen=True)
class ResourceKey:
    resource_file: str
    view_id: int

    @classmethod
    def parse(cls, raw: str) -> ResourceKey:
        file, _, vid = raw.rpartition(":")
        if not file:
            raise ValueError(f"invalid resource key {raw!r}")
        return cls(file, int(vid, 0))

    def text(self) -> str:
        return f"{self.resource_file}:{self.view_id}"


@dataclass(frozen=True)
class TextPresentation:
    value: str
    font_family: int
    face_flags: int
    point_size: int
    alignment: int
    color_index: int | None
    shadow_color_index: int | None
    shadow_offset: tuple[int, int]
    center_vertically: bool


@dataclass
class Node:
    node_id: str
    type_code: str
    tag: str
    class_name: str
    parent_id: str | None
    geometry: tuple[int, int, int, int]
    state: int
    enabled: int
    input_gate: int
    insets: tuple[int, int, int, int] | None = None
    picture_id: int | None = None
    control_state: int | None = None
    text: TextPresentation | None = None
    max_chars: int | None = None
    window: tuple[Any, ...] | None = None
    slider: tuple[int, int, int, int] | None = None
    children: list[Node] = field(default_factory=list)


def _rust_enum_variant(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))


def _text_from_patch(text: dict[str, Any]) -> TextPresentation:
    shadow = text.get("shadow_offset", (0, 0))
    return TextPresentation(
        value=str(text.get("value", "")),
        font_family=int(text["font_family"]),
        face_flags=int(text["face_flags"]),
        point_size=int(text["point_size"]),
        alignment=int(text["alignment"]),
        color_index=text.get("color_index"),
        shadow_color_index=text.get("shadow_color_index"),
        shadow_offset=(int(shadow[0]), int(shadow[1])),
        center_vertically=bool(text.get("center_vertically", False)),
    )


def _text_from_windows_child(text: dict[str, Any]) -> TextPresentation:
    shadow = text.get("shadow_offset", (0, 0))
    return TextPresentation(
        value="",
        font_family=1,
        face_flags=int(text.get("flags", 0)),
        point_size=int(text["point_size"]),
        alignment=1,
        color_index=text.get("color_index"),
        shadow_color_index=text.get("shadow_color_index"),
        shadow_offset=(int(shadow[0]), int(shadow[1])),
        center_vertically=bool(text.get("center_vertically", False)),
    )


def _require_picture(node: Node) -> int:
    if node.picture_id is None:
        raise ValueError(
            f"{node.tag!r} ({node.class_name}): missing required picture_id"
        )
    return node.picture_id


def _require_slider(node: Node) -> tuple[int, int, int, int]:
    if node.slider is None:
        raise ValueError(
            f"{node.tag!r} ({node.class_name}): missing required two-pic slider facts"
        )
    return node.slider


def _rust_str(value: str) -> str:
    rendered = json.dumps(value, ensure_ascii=False)
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: f"\\u{{{m.group(1)}}}", rendered)


def _fn_name(resource_file: str, resource_id: int) -> str:
    stem = re.sub(r"[^a-z0-9]+", "_", resource_file.removesuffix(".rsrc").casefold()).strip("_")
    return f"{stem}_{resource_id}"


def _fixed24(value: int) -> int:
    if value % 0x100:
        raise ValueError(f"fractional fixed24 value 0x{value:x}")
    return value // 0x100


def _load_node_class_substitutions(rows: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    substitutions: dict[tuple[str, str], str] = {}
    for index, row in enumerate(rows):
        view = str(row["view"])
        mac_class = str(row["mac_class"])
        windows_class = str(row["windows_class"])
        evidence = str(row.get("evidence", "")).strip()
        if not evidence:
            raise ValueError(f"{DELTAS_PATH}: node_class_substitutions[{index}] missing evidence")
        key = (view, mac_class)
        if key in substitutions:
            raise ValueError(f"{DELTAS_PATH}: duplicate node class substitution for {view} {mac_class}")
        substitutions[key] = windows_class
    return substitutions


def _load_evidence(root: Path) -> dict[str, Any]:
    with (root / STRINGS_PATH).open(encoding="utf-8", newline="") as stream:
        strings = {(r["resource_file"], int(r["group_id"]), int(r["string_index"])): r["text"]
                   for r in csv.DictReader(stream)}
    text_data = json.loads((root / TEXT_RESOURCES_PATH).read_text(encoding="utf-8"))
    styles = {(r["resource_file"], int(r["resource_id"])): r for r in text_data["text_styles"]}
    views = {ResourceKey(r["resource_file"], int(r["view_id"])): r
             for r in json.loads((root / IR_PATH).read_text(encoding="utf-8"))["views"]}
    manifest = yaml.safe_load((root / MANIFEST).read_text(encoding="utf-8"))
    deltas = yaml.safe_load((root / DELTAS_PATH).read_text(encoding="utf-8")) or {}
    win_yaml = yaml.safe_load((root / WINDOWS_VIEWS_PATH).read_text(encoding="utf-8"))
    keys, overrides, win_names = [], {}, []
    for fn in manifest["functions"]:
        for case in fn["cases"]:
            if case.get("rejected"):
                continue
            if case.get("windows_view"):
                win_names.append(str(case["windows_view"]))
                continue
            key = ResourceKey.parse(str(case["resource"]))
            keys.append(key)
            if case.get("windows_overrides"):
                overrides[key] = [{"node_id": f"0x{int(n):04x}", **p} for n, p in case["windows_overrides"].items()]
    windows_views: dict[str, list[dict]] = {}
    for view_id, row in (win_yaml.get("views") or {}).items():
        defaults = row.get("defaults", {})
        nodes = []
        for raw in row["nodes"]:
            fam = raw.get("family", {})
            nodes.append({"node_id": str(raw["id"]), "type_code": raw["type"], "tag": raw["tag"],
                          "class_name": raw["class"], "parent_id": str(raw["parent"]) if raw.get("parent") else None,
                          "geometry": tuple(int(v) for v in raw["geometry"]),
                          "state": int(raw.get("state", defaults.get("state", 1))),
                          "enabled": int(raw.get("enabled", defaults.get("enabled", 1))),
                          "input_gate": int(raw.get("input_gate", defaults.get("input_gate", 1))),
                          "insets": tuple(int(v) for v in fam["content_insets"]) if "content_insets" in fam else None,
                          "picture_id": int(fam["picture_id"]) if "picture_id" in fam else None,
                          "text": fam.get("text"), "max_chars": int(fam["max_chars"]) if "max_chars" in fam else None,
                          "window": fam.get("window")})
        windows_views[view_id] = nodes
    node_sub_rows = deltas.get("node_class_substitutions") or []
    if not isinstance(node_sub_rows, list):
        raise ValueError(f"{DELTAS_PATH}: node_class_substitutions must be a list")
    return {
        "strings": strings, "styles": styles, "views": views,
        "keys": sorted(set(keys), key=lambda k: (k.resource_file, k.view_id)),
        "overrides": overrides, "win_names": sorted(set(win_names)),
        "subs": {k: v["windows_class"] for k, v in (deltas.get("class_substitutions") or {}).items()},
        "node_class_subs": _load_node_class_substitutions(node_sub_rows),
        "text_patches": deltas.get("node_property_patches") or [],
        "child_patches": deltas.get("windows_child_nodes") or [],
        "slider_patches": deltas.get("two_pic_slider_instances") or [],
        "windows_views": windows_views,
    }


def _text_value(strings: dict, key: ResourceKey, group: int, index: int) -> str:
    return "" if index in (-1, 0xFFFF) else strings[(key.resource_file, group, index)]


def _node_id(raw: object) -> str:
    return f"0x{int(str(raw), 0):04x}"


def _resolved_class_name(
    key: ResourceKey,
    type_code: str,
    raw_class: str | None,
    subs: dict[str, str],
    node_class_subs: dict[tuple[str, str], str],
) -> str:
    class_name = subs.get(str(raw_class), str(raw_class)) if raw_class else DEFAULT_CLASSES[type_code]
    return node_class_subs.get((key.text(), class_name), class_name)


def _parse_mac_node(row: dict, key: ResourceKey, ev: dict[str, Any]) -> Node:
    type_code, family = str(row["type_code"]), row.get("family", {})
    class_name = _resolved_class_name(
        key, type_code, row.get("class_name"), ev["subs"], ev["node_class_subs"],
    )
    insets = None
    if type_code in LAYOUT_TYPES and isinstance(family.get("content_insets"), list):
        insets = tuple(_fixed24(int(v)) for v in family["content_insets"])
    picture_id = int(family["picture_id"]) if type_code in ("pict", "radb", "chkb") and "picture_id" in family else None
    control_state = (
        int(family["control_state"])
        if type_code in ("radb", "chkb") and "control_state" in family
        else None
    )
    style_id = family.get("text_style_id")
    resolved = ev["styles"].get((key.resource_file, int(style_id)), {}) if isinstance(style_id, int) else {}
    font = MAC_FONTS.get(str(resolved.get("font_name", "")).casefold(), 0)
    text, max_chars = None, None
    if type_code in ("stat", "nmbr"):
        text = TextPresentation(
            value=_text_value(ev["strings"], key, int(family.get("text_resource_id", 0)),
                              int(family.get("text_resource_index", -1))),
            font_family=font,
            face_flags=int(resolved.get("face_flags", 0)),
            point_size=int(resolved.get("point_size", 0)),
            alignment=int(family.get("text_alignment", 1)),
            color_index=None,
            shadow_color_index=None,
            shadow_offset=(0, 0),
            center_vertically=type_code == "nmbr",
        )
    elif type_code == "edit":
        text = TextPresentation(
            value="",
            font_family=font,
            face_flags=int(resolved.get("face_flags", 0)),
            point_size=int(resolved.get("point_size", 0)),
            alignment=int(family.get("text_alignment", 1)),
            color_index=None,
            shadow_color_index=None,
            shadow_offset=(0, 0),
            center_vertically=False,
        )
        max_chars = int(family.get("max_char_count", 0xFF))
    geom = row["geometry"]
    window = None
    if type_code in ("wind", "fwnd"):
        window = (0x80, 0x1F40, 1, 1, 1, 1, 0, 1) if type_code == "fwnd" and family.get("window_flags") == 0x1F40 else (8, 2, 0, 1, 1, 0, 0, 1)
    if class_name == "TInfoBarText" and text is None:
        text = TextPresentation(
            value="",
            font_family=1,
            face_flags=0,
            point_size=12,
            alignment=1,
            color_index=0x28,
            shadow_color_index=0,
            shadow_offset=(1, 1),
            center_vertically=False,
        )
    return Node(f"0x{int(row['offset']):04x}", type_code, str(row["tag"]), class_name,
                f"0x{int(row['parent_offset']):04x}" if row.get("parent_offset") is not None else None,
                (int(geom["x"]), int(geom["y"]), int(geom["width"]), int(geom["height"])),
                int(row["state"]), int(row["enabled"]), int(row["input_gate"]), insets, picture_id,
                control_state, text, max_chars, window)


def _apply_patches(flat: dict[str, Node], order: list[str], key: ResourceKey, ev: dict[str, Any]) -> None:
    for row in ev["overrides"].get(key, []):
        node = flat[row["node_id"]]
        if "enabled" in row:
            node.enabled = int(row["enabled"])
        if "content_insets" in row and node.insets is not None:
            node.insets = tuple(int(v) for v in row["content_insets"])
        if "text_source" in row and node.text:
            node.text = TextPresentation(
                value="",
                font_family=node.text.font_family,
                face_flags=node.text.face_flags,
                point_size=node.text.point_size,
                alignment=node.text.alignment,
                color_index=node.text.color_index,
                shadow_color_index=node.text.shadow_color_index,
                shadow_offset=node.text.shadow_offset,
                center_vertically=node.text.center_vertically,
            )
    for patch in ev["text_patches"]:
        if ResourceKey.parse(patch["view"]) != key:
            continue
        node = flat[_node_id(patch["node"])]
        props, text = patch["properties"], patch["properties"]["text"]
        value = node.text.value if node.text else ""
        if "resource_id" in text:
            res = ResourceKey(text.get("resource_file") or key.resource_file, key.view_id)
            value = _text_value(ev["strings"], res, int(text["resource_id"]), int(text["resource_index"]))
        presentation = _text_from_patch({**text, "value": value})
        node.text = presentation
        if "geometry" in props:
            x, y, w, h = node.geometry
            d = int(props["geometry"]["top"])
            node.geometry = (x, y + d, w, h - d)
    for patch in ev["child_patches"]:
        if ResourceKey.parse(patch["view"]) != key:
            continue
        parent_id = _node_id(patch["parent"]["node"])
        fam = patch["family"]
        child_text = fam.get("text")
        text = _text_from_windows_child(child_text) if isinstance(child_text, dict) else None
        node_id = f"windows:{parent_id}:{patch['tag']}"
        flat[node_id] = Node(node_id, patch["type"], patch["tag"], patch["class"], parent_id,
                             tuple(int(v) for v in patch["geometry"]), 1, 1, 1,
                             tuple(int(v) for v in fam["content_insets"]) if "content_insets" in fam else None,
                             int(fam["picture_id"]) if "picture_id" in fam else None,
                             None, text)
        order.append(node_id)
    for patch in ev["slider_patches"]:
        if ResourceKey.parse(patch["view"]) != key:
            continue
        node = flat[_node_id(patch["node"])]
        off = patch["off_string"]
        node.slider = (int(patch["picture_base"]), int(patch["scale"]), int(off["group"]), int(off["index"]))


def _build_tree(flat: dict[str, Node], order: list[str]) -> Node:
    roots: list[Node] = []
    for node_id in order:
        node = flat[node_id]
        node.children = []
        (roots if node.parent_id is None else flat[node.parent_id].children).append(node)
    if len(roots) != 1:
        raise ValueError(f"expected one root, found {len(roots)}")
    return roots[0]


def resolve_scenes(evidence: dict[str, Any]) -> list[tuple[str, str, Node]]:
    scenes = []
    for key in evidence["keys"]:
        mac_nodes = [_parse_mac_node(r, key, evidence) for r in evidence["views"][key]["nodes"]]
        flat, order = {n.node_id: n for n in mac_nodes}, [n.node_id for n in mac_nodes]
        _apply_patches(flat, order, key, evidence)
        scenes.append((_fn_name(key.resource_file, key.view_id), key.text(), _build_tree(flat, order)))
    for name in evidence["win_names"]:
        raw_nodes = evidence["windows_views"][name]
        flat = {raw["node_id"]: _node_from_raw(raw) for raw in raw_nodes}
        scenes.append((name, name, _build_tree(flat, [raw["node_id"] for raw in raw_nodes])))
    return scenes


def _node_from_raw(raw: dict[str, Any]) -> Node:
    fam_text = raw.get("text")
    text = _text_from_patch(fam_text) if isinstance(fam_text, dict) and "font_family" in fam_text else None
    if isinstance(fam_text, dict) and "point_size" in fam_text and text is None:
        text = _text_from_windows_child(fam_text)
    return Node(
        raw["node_id"], raw["type_code"], raw["tag"], raw["class_name"], raw.get("parent_id"),
        raw["geometry"], raw["state"], raw["enabled"], raw["input_gate"], raw.get("insets"),
        raw.get("picture_id"), raw.get("control_state"), text, raw.get("max_chars"), raw.get("window"),
        raw.get("slider"),
    )


def _interaction_disabled(node: Node) -> bool:
    return not node.enabled or not node.input_gate


def _picture_swap_ids(node: Node) -> tuple[int, int]:
    pic = _require_picture(node)
    if node.class_name in CHECKBOX_SWAP_CLASSES or node.type_code == "chkb":
        return pic & ~1, pic | 1
    return pic, pic + 1


def _emit_checked(node: Node) -> list[str]:
    if node.type_code in ("radb", "chkb") and node.control_state == 1:
        return ["Checked"]
    return []


def _emit_interaction_disabled(node: Node) -> list[str]:
    if _interaction_disabled(node):
        return ["InteractionDisabled"]
    return []


def _emit_picture_art(node: Node) -> list[str]:
    if node.picture_id is None:
        return []
    pic = node.picture_id
    if node.class_name == "TMadnessButton":
        return [f"retail_madness_picture({pic})"]
    if node.class_name == "TToggleButton":
        return [f"retail_picture({pic})"]
    if node.class_name in PICTURE_OVERLAY_CLASSES:
        idle, overlay = _picture_swap_ids(node)
        return [f"retail_picture_button({idle}, {overlay})"]
    idle, active = _picture_swap_ids(node)
    return [f"retail_picture_swap({idle}, {active})"]


def _emit_hover_help_bar() -> list[str]:
    return ["@HoverHelpBar"]


def _emit_captioned_window() -> list[str]:
    return ["@CaptionedWindow"]


def _emit_scroll_area() -> list[str]:
    return [
        "ScrollArea",
        "ScrollPosition::default()",
        "Node { overflow: Overflow::scroll_y() }",
        "Pickable",
    ]


def _emit_page_corner(node: Node) -> list[str]:
    if node.tag == "lcor":
        corner = "retail_page_corner_left()"
    elif node.tag == "rcor":
        corner = "retail_page_corner_right()"
    else:
        raise ValueError(f"unsupported page corner tag {node.tag!r}")
    lines = [
        corner,
        "Pickable { should_block_lower: false, is_hoverable: true }",
        "Button",
    ]
    lines.extend(_emit_interaction_disabled(node))
    return lines


def _emit_sideways_arrow(node: Node, *, hilite: bool) -> list[str]:
    idle, active = _picture_swap_ids(node)
    lines = ["RetailSidewaysArrow"]
    if hilite:
        lines.append("RetailSidewaysArrowHilite")
    lines.extend(_emit_interaction_disabled(node))
    lines.append(f"retail_picture_swap({idle}, {active})")
    return lines


def _emit_font_family(family: int) -> str:
    return "1" if family == 0 else str(family)


def _emit_text_lines(node: Node, pad: str, *, field: bool) -> list[str]:
    if node.text is None:
        raise ValueError(f"{node.tag!r}: missing text presentation")
    text = node.text
    lines: list[str] = []
    if field:
        mc = node.max_chars
        mc_arg = "None" if mc is None or mc < 0 else f"Some({mc})"
        lines += [
            f"{pad}    retail_edit_field()",
            f"{pad}    retail_editable_text({_rust_str(text.value)}, {mc_arg})",
        ]
    else:
        lines.append(f"{pad}    Text({_rust_str(text.value)})")
    lines.append(
        f"{pad}    retail_text_style({_emit_font_family(text.font_family)}, "
        f"{text.face_flags}, {text.point_size}, {text.alignment})"
    )
    if text.color_index is not None:
        lines.append(f"{pad}    retail_text_color(0x{int(text.color_index):x})")
    else:
        lines.append(f"{pad}    TextColor(Color::BLACK)")
    if text.shadow_color_index is not None:
        lines.append(
            f"{pad}    retail_text_shadow(0x{int(text.shadow_color_index):x}, "
            f"{text.shadow_offset[0]}, {text.shadow_offset[1]})"
        )
    if text.center_vertically:
        inset_top = int((node.insets or (0, 0, 0, 0))[1])
        lines.append(
            f"{pad}    retail_centered_text_padding({_emit_font_family(text.font_family)}, "
            f"{text.face_flags}, {text.point_size}, {node.geometry[3]}, {inset_top})"
        )
    if _interaction_disabled(node) and (field or node.type_code == "nmbr"):
        lines.append(f"{pad}    InteractionDisabled")
    return lines


def _class_lines(node: Node) -> list[str]:
    cls = node.class_name
    if cls == "TPageCorner":
        return _emit_page_corner(node)
    if cls == "TInfoBarText":
        return _emit_hover_help_bar()
    if cls == "TRadioTextCluster":
        return ["RadioGroup"]
    if cls == "TScrollView":
        lines = _emit_scroll_area()
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls in ("TCityProductionView", "TCitySiteView", "TMapPreviewView"):
        lines = ["RelativeCursorPosition"]
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls == "TSidewaysArrow":
        return _emit_sideways_arrow(node, hilite=True)
    if cls == "TRightLeftView":
        return _emit_sideways_arrow(node, hilite=False)
    if cls == "TArmyPlacard":
        return [f"retail_army_placard({_require_picture(node)})"]
    if cls == "TShipPlacard":
        return [f"retail_ship_placard({_require_picture(node)})"]
    if cls == "TPlacard":
        return [f"retail_placard({_require_picture(node)})"]
    if cls in ("TIndustryAmtBar", "TRailAmtBar"):
        lines = ["retail_production_amount_bar()"]
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls == "TTraderAmtBar":
        lines = ["retail_trade_amount_bar()"]
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls == "TNumberedArrowButton":
        lines = ["retail_numbered_arrow()"]
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls == "TTwoPicSlider":
        s = _require_slider(node)
        lines = [f"retail_two_pic_slider({s[0]}, {s[1]}, {s[2]}, {s[3]})"]
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls == "TTransportPicture":
        capacity = node.tag == "tota"
        parts = (
            "transport_gauge_capacity_parts()"
            if capacity
            else "transport_gauge_allocation_parts()"
        )
        lines = [
            f"retail_picture({_require_picture(node)})",
            parts,
        ]
        lines.extend(_emit_interaction_disabled(node))
        return lines
    if cls in CHECKBOX_CLASSES:
        lines = ["Checkbox"]
        lines.extend(_emit_checked(node))
        lines.extend(_emit_interaction_disabled(node))
        lines.extend(_emit_picture_art(node))
        return lines
    if cls in RADIO_CLASSES:
        lines = ["RadioButton"]
        if cls == "TRadioText":
            lines.append("retail_radio_text_fill()")
        lines.extend(_emit_checked(node))
        lines.extend(_emit_interaction_disabled(node))
        if cls != "TRadioText":
            lines.extend(_emit_picture_art(node))
        return lines
    if cls in BUTTON_CLASSES or (node.type_code == "cntl" and cls == DEFAULT_CLASSES["cntl"]):
        lines = ["Button"]
        lines.extend(_emit_interaction_disabled(node))
        lines.extend(_emit_picture_art(node))
        return lines
    if node.type_code in CONTAINER_TYPES | TEXT_TYPES:
        return []
    if node.type_code == "pict":
        if node.picture_id is None:
            raise ValueError(f"picture node {node.tag!r} missing picture_id")
        return [f"retail_picture({node.picture_id})"]
    raise ValueError(f"unsupported node class {cls} type={node.type_code!r} tag={node.tag!r}")


def _emit_node(node: Node, indent: int) -> list[str]:
    pad, x, y, w, h = " " * indent, *node.geometry
    lines = [f"{pad}(", f"{pad}    retail_node(fourcc!({_rust_str(node.tag)}), {x}, {y}, {w}, {h})"]
    if node.window == (0x80, 0x1F40, 1, 1, 1, 1, 0, 1):
        lines.extend(f"{pad}    {line}" for line in _emit_captioned_window())
    ins = node.insets or (0, 0, 0, 0)
    if any(ins):
        lines += [f"{pad}    Node {{ padding: UiRect {{ left: px({ins[0]}), top: px({ins[1]}), "
                  f"right: px({ins[2]}), bottom: px({ins[3]}) }} }}"]
    lines.extend(f"{pad}    {line}" for line in _class_lines(node))
    if node.text and node.type_code == "edit":
        lines.extend(_emit_text_lines(node, pad, field=True))
    elif node.text:
        lines.extend(_emit_text_lines(node, pad, field=False))
    if node.class_name in ATOMIC_CLASSES and node.children:
        raise ValueError(f"{node.tag}: atomic class {node.class_name} cannot have children")
    gauge_children = None
    if node.class_name == "TTransportPicture":
        capacity = node.tag == "tota"
        gauge_children = (
            f"{{transport_gauge_capacity_children({x})}},"
            if capacity
            else f"{{transport_gauge_allocation_children({x})}},"
        )
    if gauge_children is not None or node.children:
        lines.append(f"{pad}    Children [")
        if gauge_children is not None:
            lines.append(f"{pad}        {gauge_children}")
        for child in node.children:
            chunk = _emit_node(child, indent + 8)
            chunk[-1] += ","
            lines.extend(chunk)
        lines.append(f"{pad}    ]")
    lines.append(f"{pad})")
    return lines


def render(scenes: list[tuple[str, str, Node]]) -> str:
    header = (
        "// @generated by tools.ui_rust_codegen. Do not edit by hand.\n"
        "#![allow(dead_code, clippy::identity_op, unused_imports)]\n\n"
        "use super::hover_help::HoverHelpBar;\n"
        "use super::retail::*;\n"
        "use super::retail_page_corner::{retail_page_corner_left, retail_page_corner_right};\n"
        "use super::retail_sideways_arrow::{RetailSidewaysArrow, RetailSidewaysArrowHilite};\n"
        "use super::window::CaptionedWindow;\n"
        "use bevy::prelude::*;\n"
        "use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition, ScrollPosition};\n"
        "use bevy::ui_widgets::{Button, Checkbox, RadioButton, RadioGroup, ScrollArea};\n"
        "use imperialism_formats::fourcc;\n\n"
        "pub const LOGICAL_RESOLUTION: [u32; 2] = [640, 480];\n\n"
    )
    body = []
    for fn, view_name, root in scenes:
        body += ["#[rustfmt::skip]", f"pub fn {fn}() -> impl Scene {{", "    bsn! {",
                 f"        retail_view({_rust_str(view_name)})", "        Children ["]
        chunk = _emit_node(root, 12)
        chunk[-1] += ","
        body.extend(chunk)
        body += ["        ]", "    }", "}", ""]
    return header + "\n".join(body)


def _load_city_buildings(root: Path, scene_keys: set[ResourceKey]) -> tuple[list[dict], ResourceKey]:
    deltas = yaml.safe_load((root / DELTAS_PATH).read_text(encoding="utf-8")) or {}
    context = f"{DELTAS_PATH}: city_buildings"
    section = deltas.get("city_buildings")
    if not isinstance(section, dict):
        raise ValueError(f"{context}: missing city_buildings section")
    if set(section) != {"view", "evidence", "visuals"}:
        raise ValueError(f"{context}: expected view, evidence, and visuals")
    if not str(section["evidence"]).strip():
        raise ValueError(f"{context}: evidence is required")
    view = ResourceKey.parse(str(section["view"]))
    if view not in scene_keys:
        raise ValueError(f"{context}: view {view.text()} is not in the native Rust UI")
    visuals_raw = section["visuals"]
    if not isinstance(visuals_raw, list) or len(visuals_raw) != 16:
        raise ValueError(f"{context}/visuals: expected exactly 16 entries")
    visuals: list[dict] = []
    slots: set[str] = set()
    for index, raw_row in enumerate(visuals_raw):
        row_context = f"{context}/visuals[{index}]"
        if not isinstance(raw_row, dict) or set(raw_row) != {"slot", "origin", "dialog"}:
            raise ValueError(f"{row_context}: expected slot, origin, and dialog")
        slot = str(raw_row["slot"])
        if not slot or slot in slots:
            raise ValueError(f"{row_context}: duplicate or empty slot {slot!r}")
        slots.add(slot)
        origin = raw_row["origin"]
        if not isinstance(origin, list) or len(origin) != 2:
            raise ValueError(f"{row_context}/origin: expected [x, y]")
        dialog = ResourceKey.parse(str(raw_row["dialog"]))
        if dialog not in scene_keys:
            raise ValueError(f"{row_context}: dialog {dialog.text()} is not in the native Rust UI")
        visuals.append({"slot": slot, "origin": (int(origin[0]), int(origin[1])), "dialog": dialog})
    return visuals, view


def _load_city_building_actions(root: Path, buildings_view: ResourceKey) -> list[dict]:
    deltas = yaml.safe_load((root / DELTAS_PATH).read_text(encoding="utf-8")) or {}
    context = f"{DELTAS_PATH}: city_building_actions"
    section = deltas.get("city_building_actions")
    if not isinstance(section, dict):
        raise ValueError(f"{context}: missing city_building_actions section")
    if set(section) != {"view", "evidence", "actions"}:
        raise ValueError(f"{context}: expected view, evidence, and actions")
    if not str(section["evidence"]).strip():
        raise ValueError(f"{context}: evidence is required")
    view = ResourceKey.parse(str(section["view"]))
    if view != buildings_view:
        raise ValueError(
            f"{context}: view must match city_buildings view {buildings_view.text()}"
        )
    slots_by_group = (
        "textile_mill", "clothing_factory", "steel_mill", "metalworks",
        "lumber_mill", "furniture_factory", "oil_refinery", "power_plant",
    )
    actions_raw = section["actions"]
    if not isinstance(actions_raw, list) or not actions_raw:
        raise ValueError(f"{context}/actions: expected a non-empty list")
    actions: list[dict] = []
    for index, raw_row in enumerate(actions_raw):
        row_context = f"{context}/actions[{index}]"
        if not isinstance(raw_row, dict):
            raise ValueError(f"{row_context}: expected a mapping")
        expected_fields = {"slot", "level", "picture_id", "frame_count", "origin", "frame_size"}
        if set(raw_row) != expected_fields:
            raise ValueError(f"{row_context}: malformed city building action")
        picture_id = int(raw_row["picture_id"])
        group = (picture_id - 15000) // 10
        level = (picture_id % 10) // 3 + 1
        slot = str(raw_row["slot"])
        if group >= len(slots_by_group) or slot != slots_by_group[group] or int(raw_row["level"]) != level:
            raise ValueError(f"{row_context}: slot or level does not match picture id")
        frame_count = int(raw_row["frame_count"])
        if not 0 < frame_count <= 255:
            raise ValueError(f"{row_context}: frame count must fit a nonzero byte")
        origin = raw_row["origin"]
        frame_size = raw_row["frame_size"]
        if not isinstance(origin, list) or len(origin) != 2:
            raise ValueError(f"{row_context}/origin: expected [x, y]")
        if not isinstance(frame_size, list) or len(frame_size) != 2:
            raise ValueError(f"{row_context}/frame_size: expected [w, h]")
        origin_pair = (int(origin[0]), int(origin[1]))
        frame_size_pair = (int(frame_size[0]), int(frame_size[1]))
        if min(*origin_pair, *frame_size_pair) < 0 or min(frame_size_pair) == 0:
            raise ValueError(f"{row_context}: origin must be nonnegative and frame size positive")
        if origin_pair[0] + frame_size_pair[0] > 640 or origin_pair[1] + frame_size_pair[1] > 480:
            raise ValueError(f"{row_context}: frame falls outside the retail canvas")
        actions.append({
            "slot": slot,
            "level": level,
            "picture_id": picture_id,
            "frame_count": frame_count,
            "origin": origin_pair,
            "frame_size": frame_size_pair,
        })
    return actions


def render_city_building_layout(root: Path) -> str:
    evidence = _load_evidence(root)
    scene_keys = set(evidence["keys"])
    visuals, view = _load_city_buildings(root, scene_keys)
    actions = _load_city_building_actions(root, view)
    lines = [
        "// @generated by tools.ui_rust_codegen. Do not edit by hand.",
        "",
        "use super::building_visuals::{CityBuildingActionVisual, CityBuildingVisual};",
        "use imperialism_core::CityFacilitySlot;",
        "use imperialism_formats::PictureId;",
        "",
        "const fn building(slot: CityFacilitySlot, x: i32, y: i32) -> CityBuildingVisual {",
        "    CityBuildingVisual { slot, origin: [x, y] }",
        "}",
        "",
        "const fn action(",
        "    slot: CityFacilitySlot,",
        "    level: u8,",
        "    picture: i16,",
        "    frames: u8,",
        "    x: i32,",
        "    y: i32,",
        "    w: i32,",
        "    h: i32,",
        ") -> CityBuildingActionVisual {",
        "    CityBuildingActionVisual {",
        "        slot,",
        "        level,",
        "        picture_id: PictureId::new(picture),",
        "        frame_count: frames,",
        "        origin: [x, y],",
        "        frame_size: [w, h],",
        "    }",
        "}",
        "",
        "pub(in crate::ui::city) const CITY_BUILDINGS: &[CityBuildingVisual] = &[",
    ]
    for visual in visuals:
        x, y = visual["origin"]
        lines.append(
            f"    building(CityFacilitySlot::{_rust_enum_variant(visual['slot'])}, {x}, {y}),"
        )
    lines.extend(["];", "", "pub(in crate::ui::city) const CITY_BUILDING_ACTIONS: &[CityBuildingActionVisual] = &["])
    for action in actions:
        x, y = action["origin"]
        w, h = action["frame_size"]
        lines.append(
            f"    action(CityFacilitySlot::{_rust_enum_variant(action['slot'])}, "
            f"{action['level']}, {action['picture_id']}, {action['frame_count']}, "
            f"{x}, {y}, {w}, {h}),"
        )
    lines.extend(["];", ""])
    return "\n".join(lines)


def generate(root: Path) -> tuple[str, list[tuple[str, str, Node]]]:
    evidence = _load_evidence(root)
    scenes = resolve_scenes(evidence)
    return render(scenes), scenes


def write_output(root: Path) -> tuple[Path, Path]:
    out = resolve_repo_path(root, RUST_OUT)
    city_out = resolve_repo_path(root, RUST_CITY_LAYOUT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    city_out.parent.mkdir(parents=True, exist_ok=True)
    output, _ = generate(root)
    out.write_text(output, encoding="utf-8")
    city_out.write_text(render_city_building_layout(root), encoding="utf-8")
    return out, city_out


def is_current(root: Path) -> bool:
    out = resolve_repo_path(root, RUST_OUT)
    city_out = resolve_repo_path(root, RUST_CITY_LAYOUT_OUT)
    if not out.is_file() or not city_out.is_file():
        return False
    output, _ = generate(root)
    city_layout = render_city_building_layout(root)
    return (
        out.read_text(encoding="utf-8") == output
        and city_out.read_text(encoding="utf-8") == city_layout
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = repo_root_from_file(__file__, levels_up=1)
    if args.write:
        ui_out, city_out = write_output(root)
        print(f"wrote {ui_out}")
        print(f"wrote {city_out}")
    if args.check and not is_current(root):
        raise SystemExit("generated Rust UI is stale; run tools.ui_rust_codegen --write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
