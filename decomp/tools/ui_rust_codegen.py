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
CHECKED_CLASSES = frozenset(
    ("TCzechBox", "TToggleButton", "TMadnessButton", "TRadioPictureButton",
     "TOverlayRadioButton", "TCivilianButton", "TRadioText", "TPageCorner")
)
_BTN = ("retail_picture_button({idle}, {active})",)
_RADIO = ("retail_radio_picture_button({idle}, {active})",)
_SWAP = ("retail_picture_swap_button({idle}, {active})",)
CLASS_RENDERERS: dict[str, tuple[str, ...]] = {
    **dict.fromkeys(("T2PictureButton", "TClickZone", "TControl", "TDealTabControl", "TPictureNumberText"), _BTN),
    **dict.fromkeys(("TOverlayRadioButton", "TRadioPictureButton", "TCivilianButton"), _RADIO),
    **dict.fromkeys(("TTextPictureButton", "TUpDownPictureButton"), _SWAP),
    "TArmyPlacard": ("retail_army_placard({picture_id})",),
    "TCityProductionView": ("retail_pointer_canvas()",), "TCitySiteView": ("retail_pointer_canvas()",),
    "TCzechBox": ("retail_checkbox({idle}, {active})",),
    "TDropShadowNumberText": (), "TEditText": (), "TMyNumberText": (), "TNumberText": (),
    "TInfoBarText": ("retail_hover_help_bar()",),
    "TMadnessButton": ("retail_madness_checkbox({picture_id})",),
    "TMapPreviewView": ("retail_pointer_canvas()",),
    "TNumberedArrowButton": ("retail_numbered_arrow()",),
    "TPictureButton": ("retail_picture_button_overlay({idle}, {overlay})",),
    "TPlacard": ("retail_placard({picture_id})",),
    "TRadioText": ("retail_radio_text()",), "TRadioTextCluster": ("retail_radio_cluster()",),
    "TScrollView": ("retail_scroll_area()",),
    "TShipPlacard": ("retail_ship_placard({picture_id})",),
    "TToggleButton": ("retail_toggle_picture({picture_id})",),
    "TTwoPicSlider": ("retail_two_pic_slider({pic_base}, {scale}, {off_group}, {off_index})",),
    "TIndustryAmtBar": ("retail_amount_bar(AmountBarStyle::Production)",),
    "TRailAmtBar": ("retail_amount_bar(AmountBarStyle::Production)",),
    "TTraderAmtBar": ("retail_amount_bar(AmountBarStyle::Trade)",),
}
INTERACTIVE_CLASSES = frozenset(CLASS_RENDERERS) | {"TSidewaysArrow", "TPageCorner", "TTransportPicture"}


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
    text: dict[str, Any] | None = None
    max_chars: int | None = None
    window: tuple[Any, ...] | None = None
    slider: tuple[int, int, int, int] | None = None
    children: list[Node] = field(default_factory=list)


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
    return {
        "strings": strings, "styles": styles, "views": views,
        "keys": sorted(set(keys), key=lambda k: (k.resource_file, k.view_id)),
        "overrides": overrides, "win_names": sorted(set(win_names)),
        "subs": {k: v["windows_class"] for k, v in (deltas.get("class_substitutions") or {}).items()},
        "text_patches": deltas.get("node_property_patches") or [],
        "child_patches": deltas.get("windows_child_nodes") or [],
        "slider_patches": deltas.get("two_pic_slider_instances") or [],
        "windows_views": windows_views,
    }


def _text_value(strings: dict, key: ResourceKey, group: int, index: int) -> str:
    return "" if index in (-1, 0xFFFF) else strings[(key.resource_file, group, index)]


def _node_id(raw: object) -> str:
    return f"0x{int(str(raw), 0):04x}"


def _parse_mac_node(row: dict, key: ResourceKey, subs: dict, strings: dict, styles: dict) -> Node:
    type_code, family = str(row["type_code"]), row.get("family", {})
    class_name = subs.get(str(row["class_name"]), str(row["class_name"])) if row.get("class_name") else DEFAULT_CLASSES[type_code]
    insets = None
    if type_code in LAYOUT_TYPES and isinstance(family.get("content_insets"), list):
        insets = tuple(_fixed24(int(v)) for v in family["content_insets"])
    picture_id = int(family["picture_id"]) if type_code in ("pict", "radb", "chkb") and "picture_id" in family else None
    style_id = family.get("text_style_id")
    resolved = styles.get((key.resource_file, int(style_id)), {}) if isinstance(style_id, int) else {}
    font = MAC_FONTS.get(str(resolved.get("font_name", "")).casefold(), 0)
    text, max_chars = None, None
    if type_code in ("stat", "nmbr"):
        text = {"value": _text_value(strings, key, int(family.get("text_resource_id", 0)),
                                      int(family.get("text_resource_index", -1))),
                "font_family": font, "face_flags": int(resolved.get("face_flags", 0)),
                "point_size": int(resolved.get("point_size", 0)), "alignment": int(family.get("text_alignment", 1)),
                "color_index": None, "shadow_color_index": None, "shadow_offset": (0, 0), "center_vertically": False}
    elif type_code == "edit":
        text = {"value": "", "font_family": font, "face_flags": int(resolved.get("face_flags", 0)),
                "point_size": int(resolved.get("point_size", 0)), "alignment": int(family.get("text_alignment", 1)),
                "color_index": None, "shadow_color_index": None, "shadow_offset": (0, 0), "center_vertically": False}
        max_chars = int(family.get("max_char_count", 0xFF))
    geom = row["geometry"]
    enabled = int(row["enabled"])
    if class_name in ("TPictureButton", "T2PictureButton") and int(row["state"]) != 0:
        enabled = 1
    window = None
    if type_code in ("wind", "fwnd"):
        window = (0x80, 0x1F40, 1, 1, 1, 1, 0, 1) if type_code == "fwnd" and family.get("window_flags") == 0x1F40 else (8, 2, 0, 1, 1, 0, 0, 1)
    return Node(f"0x{int(row['offset']):04x}", type_code, str(row["tag"]), class_name,
                f"0x{int(row['parent_offset']):04x}" if row.get("parent_offset") is not None else None,
                (int(geom["x"]), int(geom["y"]), int(geom["width"]), int(geom["height"])),
                int(row["state"]), enabled, int(row["input_gate"]), insets, picture_id, text, max_chars, window)


def _apply_patches(flat: dict[str, Node], order: list[str], key: ResourceKey, ev: dict[str, Any]) -> None:
    for row in ev["overrides"].get(key, []):
        node = flat[row["node_id"]]
        if "enabled" in row:
            node.enabled = int(row["enabled"])
        if "content_insets" in row and node.insets is not None:
            node.insets = tuple(int(v) for v in row["content_insets"])
        if "text_source" in row and node.text:
            node.text["value"] = None
    for patch in ev["text_patches"]:
        if ResourceKey.parse(patch["view"]) != key:
            continue
        node = flat[_node_id(patch["node"])]
        props, text = patch["properties"], patch["properties"]["text"]
        value = (node.text or {}).get("value", "")
        if "resource_id" in text:
            res = ResourceKey(text.get("resource_file") or key.resource_file, key.view_id)
            value = _text_value(ev["strings"], res, int(text["resource_id"]), int(text["resource_index"]))
        node.text = {"value": value, "font_family": int(text["font_family"]), "face_flags": int(text["face_flags"]),
                     "point_size": int(text["point_size"]), "alignment": int(text["alignment"]),
                     "color_index": text.get("color_index"), "shadow_color_index": text.get("shadow_color_index"),
                     "shadow_offset": tuple(text.get("shadow_offset", (0, 0))), "center_vertically": False}
        if "geometry" in props:
            x, y, w, h = node.geometry
            d = int(props["geometry"]["top"])
            node.geometry = (x, y + d, w, h - d)
    for patch in ev["child_patches"]:
        if ResourceKey.parse(patch["view"]) != key:
            continue
        parent_id = _node_id(patch["parent"]["node"])
        fam = patch["family"]
        node_id = f"windows:{parent_id}:{patch['tag']}"
        flat[node_id] = Node(node_id, patch["type"], patch["tag"], patch["class"], parent_id,
                             tuple(int(v) for v in patch["geometry"]), 1, 1, 1,
                             tuple(int(v) for v in fam["content_insets"]) if "content_insets" in fam else None,
                             int(fam["picture_id"]) if "picture_id" in fam else None, fam.get("text"))
        order.append(node_id)
    for patch in ev["slider_patches"]:
        if ResourceKey.parse(patch["view"]) != key:
            continue
        node = flat[_node_id(patch["node"])]
        off = patch["off_string"]
        node.slider = (int(patch["picture_base"]), int(patch["scale"]), int(off["group"]), int(off["index"]))


def _build_tree(flat: dict[str, Node], order: list[str]) -> list[Node]:
    roots = []
    for node_id in order:
        node = flat[node_id]
        node.children = []
        (roots if node.parent_id is None else flat[node.parent_id].children).append(node)
    if len(roots) != 1:
        raise ValueError(f"expected one root, found {len(roots)}")
    return roots


def resolve_scenes(root: Path) -> list[tuple[str, str, list[Node]]]:
    ev = _load_evidence(root)
    scenes = []
    for key in ev["keys"]:
        mac_nodes = [_parse_mac_node(r, key, ev["subs"], ev["strings"], ev["styles"]) for r in ev["views"][key]["nodes"]]
        flat, order = {n.node_id: n for n in mac_nodes}, [n.node_id for n in mac_nodes]
        _apply_patches(flat, order, key, ev)
        scenes.append((_fn_name(key.resource_file, key.view_id), key.text(), _build_tree(flat, order)))
    for name in ev["win_names"]:
        raw_nodes = ev["windows_views"][name]
        flat = {raw["node_id"]: Node(**raw) for raw in raw_nodes}
        scenes.append((name, name, _build_tree(flat, [raw["node_id"] for raw in raw_nodes])))
    return scenes


def _swap_ids(node: Node) -> tuple[int, int]:
    pic = int(node.picture_id or 0)
    return (pic & ~1, pic | 1) if node.class_name == "TCzechBox" or node.type_code == "chkb" else (pic, pic + 1)


def _ctx(node: Node) -> dict[str, Any]:
    idle, active = _swap_ids(node)
    s = node.slider or (0, 0, 0, 0)
    return {"idle": idle, "active": active, "overlay": idle + 1, "picture_id": int(node.picture_id or 0),
            "pic_base": s[0], "scale": s[1], "off_group": s[2], "off_index": s[3],
            "owner_left": node.geometry[0], "capacity": str(node.tag == "tota").lower()}


def _retail_text(node: Node, field: bool) -> str:
    text = node.text or {}
    opt = lambda k: "None" if text.get(k) is None else f"Some({int(text[k])})"
    off = text.get("shadow_offset", (0, 0))
    spec = (f"RetailTextSpec {{ text: {_rust_str(text.get('value') or '')}, "
            f"font_family: {int(text.get('font_family', 0))}, face_flags: {int(text.get('face_flags', 0))}, "
            f"point_size: {int(text.get('point_size', 0))}, alignment: {int(text.get('alignment', 1))}, "
            f"color_index: {opt('color_index')}, shadow_color_index: {opt('shadow_color_index')}, "
            f"shadow_offset: ({int(off[0])}, {int(off[1])}), "
            f"center_vertically: {str(bool(text.get('center_vertically'))).lower()} }}")
    if field:
        mc = node.max_chars
        mc = None if mc is not None and mc < 0 else mc
        return f"retail_text_field({spec}, {'None' if mc is None else f'Some({mc})'})"
    return f"retail_text({spec}, {node.geometry[3]}, {int((node.insets or (0, 0, 0, 0))[1])})"


def class_has_renderer(class_name: str, type_code: str) -> bool:
    return (class_name in ("TSidewaysArrow", "TPageCorner", "TTransportPicture", *CLASS_RENDERERS)
            or type_code in CONTAINER_TYPES | TEXT_TYPES or type_code == "pict" or type_code != "cntl")


def _class_lines(node: Node, parent: Node | None, view_name: str) -> list[str]:
    if view_name == "Startup.rsrc:1501" and node.tag == "glob":
        i, a = _swap_ids(node)
        return [f"retail_picture_button({i}, {a})"]
    if node.class_name == "TSidewaysArrow":
        i, a = _swap_ids(node)
        fn = "retail_right_left_arrow" if parent and parent.class_name == "TTransportPicture" else "retail_sideways_arrow"
        return [f"{fn}({i}, {a})"]
    if node.class_name == "TPageCorner" and node.tag in ("lcor", "rcor"):
        return [f"retail_page_corner(RetailPageCorner::{'Left' if node.tag == 'lcor' else 'Right'})"]
    if node.class_name == "TTransportPicture":
        c = _ctx(node)
        return [f"retail_picture({c['picture_id']})", f"retail_transport_gauge({c['owner_left']}, {c['capacity']})"]
    if node.class_name in CLASS_RENDERERS:
        tpl = CLASS_RENDERERS[node.class_name]
        if tpl and node.picture_id is None and node.class_name not in ATOMIC_CLASSES:
            return []
        return [t.format(**_ctx(node)) for t in tpl]
    if node.type_code in CONTAINER_TYPES | TEXT_TYPES:
        return []
    if node.type_code == "pict" and node.picture_id is not None:
        return [f"retail_picture({node.picture_id})"]
    if node.type_code == "cntl":
        raise ValueError(f"unsupported control class {node.class_name} tag={node.tag!r}")
    return []


def _emit_node(node: Node, parent: Node | None, view_name: str, indent: int) -> list[str]:
    pad, x, y, w, h = " " * indent, *node.geometry
    lines = ["(", f"{pad}    retail_node(fourcc!({_rust_str(node.tag)}), {x}, {y}, {w}, {h})"]
    if node.window == (0x80, 0x1F40, 1, 1, 1, 1, 0, 1):
        lines.append(f"{pad}    retail_captioned_window()")
    ins = node.insets or (0, 0, 0, 0)
    if any(ins):
        lines += [f"{pad}    Node {{ padding: UiRect {{ left: px({ins[0]}), top: px({ins[1]}), "
                  f"right: px({ins[2]}), bottom: px({ins[3]}) }} }}"]
    checked = bool(node.state) and node.class_name in CHECKED_CLASSES
    disabled = (not node.enabled or not node.input_gate) and (node.class_name in INTERACTIVE_CLASSES or node.type_code in ("edit", "nmbr"))
    if checked or disabled:
        lines.append(f"{pad}    retail_interaction_state({str(checked).lower()}, {str(disabled).lower()})")
    lines.extend(f"{pad}    {line}" for line in _class_lines(node, parent, view_name))
    if node.text and node.type_code == "edit":
        lines.append(f"{pad}    {_retail_text(node, True)}")
    elif node.text and node.class_name != "TInfoBarText":
        lines.append(f"{pad}    {_retail_text(node, False)}")
    if node.class_name in ATOMIC_CLASSES and node.children:
        raise ValueError(f"{node.tag}: atomic class {node.class_name} cannot have children")
    if node.children:
        lines.append(f"{pad}    Children [")
        for child in node.children:
            chunk = _emit_node(child, node, view_name, indent + 8)
            chunk[-1] += ","
            lines.extend(chunk)
        lines.append(f"{pad}    ]")
    lines.append(f"{pad})")
    return lines


def render(root: Path) -> str:
    header = ("// @generated by tools.ui_rust_codegen. Do not edit by hand.\n"
              "#![allow(dead_code, clippy::identity_op)]\n\nuse super::retail::*;\n"
              "use bevy::prelude::*;\nuse imperialism_formats::fourcc;\n\n"
              "pub const LOGICAL_RESOLUTION: [u32; 2] = [640, 480];\n\n")
    body = []
    for fn, view_name, roots in resolve_scenes(root):
        body += ["#[rustfmt::skip]", f"pub fn {fn}() -> impl Scene {{", "    bsn! {",
                 f"        retail_view({_rust_str(view_name)})", "        Children ["]
        for root_node in roots:
            chunk = _emit_node(root_node, None, view_name, 12)
            chunk[-1] += ","
            body.extend(chunk)
        body += ["        ]", "    }", "}", ""]
    return header + "\n".join(body)


def encountered_classes(root: Path) -> set[str]:
    out: set[str] = set()
    for _, _, roots in resolve_scenes(root):
        stack = list(roots)
        while stack:
            node = stack.pop()
            out.add(node.class_name)
            stack.extend(node.children)
    return out


def write_output(root: Path) -> Path:
    out = resolve_repo_path(root, RUST_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(root), encoding="utf-8")
    return out


def is_current(root: Path) -> bool:
    out = resolve_repo_path(root, RUST_OUT)
    return out.is_file() and out.read_text(encoding="utf-8") == render(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = repo_root_from_file(__file__, levels_up=1)
    render(root)
    if args.write:
        print(f"wrote {write_output(root)}")
    if args.check and not is_current(root):
        raise SystemExit("generated Rust UI is stale; run tools.ui_rust_codegen --write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
