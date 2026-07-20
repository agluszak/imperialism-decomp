#!/usr/bin/env python3
"""Generate turn-event UI factory TUs from committed Mac View resource IR.

The Mac resource oracle owns hierarchy and serialized widget properties.  The
committed Windows manifest owns function addresses, prototypes, dispatch cases,
and explicit Windows-only exceptions.  Neither the Mac retail image nor the
original Windows executable is consulted by normal generation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from tools.common.repo import repo_root_from_file, resolve_repo_path


MANIFEST_PATH = "config/ui_factory_codegen.yml"
IR_PATH = "vendor/macos_codewarrior/evidence/resources/ui_views.json"
WINDOWS_RECIPE_PATH = "config/ui_factory_windows.json"
FORMAT_VERSION = 1
EMISSION_MODES = frozenset(("expanded", "compact", "resource_recipe"))

DEFAULT_CLASSES = {
    "view": "TView",
    "pict": "TPicture",
    "cntl": "TControl",
    "stat": "TStaticText",
    "clus": "TCluster",
    "tevw": "TTEView",
    "edit": "TEditText",
    "nmbr": "TNumberText",
    "wind": "TWindow",
    "fwnd": "TFloatWindow",
}

# Cross-platform spelling differences that are independently represented by a
# real Windows class.  This is a naming bridge only; it assigns no inheritance.
CLASS_ALIASES = {
    "TToolbarCluster": "TToolBarCluster",
    "TMyWindow": "TWindow",
}

LAYOUT_FAMILIES = frozenset(("pict", "cntl", "stat", "clus", "edit", "nmbr"))


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
    windows_only: bool
    evidence: str


@dataclass(frozen=True)
class UiFactoryRecipe:
    address: int
    name: str
    prototype: str
    emission: str
    cases: tuple[UiCaseRecipe, ...]

    @property
    def output_name(self) -> str:
        return f"turn_event_dialog_factory_{self.address:08x}.cpp"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_recipes(repo_root: Path) -> list[UiFactoryRecipe]:
    path = repo_root / MANIFEST_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
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
        addresses.add(address)
        names.add(name)
        emission = str(row.get("emission", "expanded"))
        if emission not in EMISSION_MODES:
            raise ValueError(
                f"{MANIFEST_PATH}: 0x{address:08x} has invalid emission {emission!r}"
            )
        cases: list[UiCaseRecipe] = []
        events: set[int] = set()
        for case_row in row.get("cases", []):
            event = int(case_row["event"])
            if event in events:
                raise ValueError(
                    f"{MANIFEST_PATH}: 0x{address:08x} has duplicate event 0x{event:x}"
                )
            events.add(event)
            windows_only = bool(case_row.get("windows_only", False))
            resource_raw = case_row.get("resource")
            resource = UiResourceKey.parse(str(resource_raw)) if resource_raw else None
            evidence = str(case_row.get("evidence", ""))
            if windows_only == (resource is not None):
                raise ValueError(
                    f"{MANIFEST_PATH}: 0x{address:08x}/0x{event:x} must have exactly "
                    "one of resource or windows_only"
                )
            if windows_only and not evidence:
                raise ValueError(
                    f"{MANIFEST_PATH}: Windows-only 0x{address:08x}/0x{event:x} "
                    "requires an evidence address"
                )
            cases.append(UiCaseRecipe(event, resource, windows_only, evidence))
        if not cases:
            raise ValueError(f"{MANIFEST_PATH}: 0x{address:08x} has no cases")
        recipes.append(
            UiFactoryRecipe(
                address=address,
                name=name,
                prototype=str(row["prototype"]),
                emission=emission,
                cases=tuple(cases),
            )
        )
    recipes.sort(key=lambda recipe: recipe.address)
    return recipes


def load_ui_views(repo_root: Path) -> dict[UiResourceKey, dict]:
    path = repo_root / IR_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    views: dict[UiResourceKey, dict] = {}
    for row in data.get("views", []):
        key = UiResourceKey(str(row["resource_file"]), int(row["view_id"]))
        if key in views:
            raise ValueError(f"{IR_PATH}: duplicate resource key {key.text()}")
        views[key] = row
    return views


def load_windows_recipes(repo_root: Path) -> dict[str, dict]:
    path = repo_root / WINDOWS_RECIPE_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format_version") != FORMAT_VERSION:
        raise ValueError(
            f"{WINDOWS_RECIPE_PATH}: unsupported format_version "
            f"{data.get('format_version')!r}"
        )
    functions = data.get("functions")
    if not isinstance(functions, dict):
        raise ValueError(f"{WINDOWS_RECIPE_PATH}: functions must be an object")
    return functions


def _resolved_class(node: dict) -> str:
    class_name = str(node.get("class_name") or "")
    if class_name:
        return CLASS_ALIASES.get(class_name, class_name)
    try:
        return DEFAULT_CLASSES[str(node["type_code"])]
    except KeyError as exc:
        raise ValueError(f"no Windows default class for {node.get('type_code')!r}") from exc


def validate(
    repo_root: Path,
    recipes: Iterable[UiFactoryRecipe],
    views: dict,
    windows_recipes: dict[str, dict] | None = None,
) -> list[str]:
    recipe_list = list(recipes)
    errors: list[str] = []
    include_dir = repo_root / "include" / "game"
    referenced: set[UiResourceKey] = set()
    for recipe in recipe_list:
        windows_function = None
        if recipe.emission == "resource_recipe":
            windows_function = (windows_recipes or {}).get(f"0x{recipe.address:08x}")
            if not isinstance(windows_function, dict):
                errors.append(
                    f"0x{recipe.address:08x}: missing {WINDOWS_RECIPE_PATH} entry"
                )
            elif len(recipe.cases) > 1 and set(
                windows_function.get("case_order", [])
            ) != {f"0x{case.event:04x}" for case in recipe.cases}:
                errors.append(
                    f"0x{recipe.address:08x}: Windows case_order does not exactly "
                    "cover manifest events"
                )
        expected_name = f"{recipe.name}("
        if expected_name not in recipe.prototype:
            errors.append(
                f"0x{recipe.address:08x}: prototype does not declare {recipe.name}"
            )
        for case in recipe.cases:
            if case.resource is None:
                continue
            referenced.add(case.resource)
            view = views.get(case.resource)
            if view is None:
                errors.append(
                    f"0x{recipe.address:08x}/0x{case.event:x}: missing {case.resource.text()}"
                )
                continue
            if int(view["view_id"]) != case.event:
                errors.append(
                    f"0x{recipe.address:08x}/0x{case.event:x}: resource ID is not the "
                    f"Windows event ID ({case.resource.text()})"
                )
            if not view.get("nodes"):
                errors.append(
                    f"0x{recipe.address:08x}/0x{case.event:x}: resource has no decoded nodes"
                )
            for node in view.get("nodes", []):
                class_name = _resolved_class(node)
                if not (include_dir / f"{class_name}.h").is_file():
                    errors.append(
                        f"{case.resource.text()} node 0x{int(node['offset']):x}: "
                        f"missing Windows header include/game/{class_name}.h"
                    )
            if windows_function is not None:
                case_recipe = windows_function.get("cases", {}).get(
                    f"0x{case.event:04x}"
                )
                if not isinstance(case_recipe, dict):
                    errors.append(
                        f"0x{recipe.address:08x}/0x{case.event:x}: missing Windows case recipe"
                    )
                    continue
                if case_recipe.get("resource") != case.resource.text():
                    errors.append(
                        f"0x{recipe.address:08x}/0x{case.event:x}: Windows recipe resource "
                        "does not match manifest"
                    )
                node_rows = case_recipe.get("nodes", {})
                skipped = set(case_recipe.get("skip_offsets", []))
                expected_offsets = {
                    f"0x{int(node['offset']):04x}" for node in view.get("nodes", [])
                }
                if set(node_rows) | skipped != expected_offsets:
                    errors.append(
                        f"0x{recipe.address:08x}/0x{case.event:x}: Windows node recipes "
                        "do not cover the resource offsets exactly"
                    )
                for node in view.get("nodes", []):
                    offset = f"0x{int(node['offset']):04x}"
                    if offset in skipped:
                        continue
                    node_recipe = node_rows.get(offset, {})
                    if node_recipe.get("emission") not in ("compact", "expanded"):
                        errors.append(
                            f"{case.resource.text()} node {offset}: Windows emission "
                            "must be compact or expanded"
                        )
                    if node_recipe.get("allocation") not in ("local", "shared"):
                        errors.append(
                            f"{case.resource.text()} node {offset}: Windows allocation "
                            "must be local or shared"
                        )
                    if node_recipe.get("control_value", "zero") not in (
                        "zero",
                        "resource",
                    ):
                        errors.append(
                            f"{case.resource.text()} node {offset}: Windows control_value "
                            "must be zero or resource"
                        )
                    class_name = str(node_recipe.get("class") or _resolved_class(node))
                    if not (include_dir / f"{class_name}.h").is_file():
                        errors.append(
                            f"{case.resource.text()} node {offset}: Windows recipe class "
                            f"include/game/{class_name}.h is missing"
                        )
                    family = node.get("family", {})
                    for operation in node_recipe.get("operations", []):
                        if operation.get("op") == "text_binding" and node.get(
                            "type_code"
                        ) in ("stat", "nmbr"):
                            args = operation.get("args", [])
                            expected_id = int(family.get("text_resource_id", -2))
                            expected_index = int(family.get("text_resource_index", -2))
                            actual_id = int(args[0]) & 0xFFFF if len(args) > 1 else -1
                            actual_index = int(args[1]) & 0xFFFF if len(args) > 1 else -1
                            if (actual_id, actual_index) != (
                                expected_id,
                                expected_index,
                            ):
                                errors.append(
                                    f"{case.resource.text()} node {offset}: text binding "
                                    "does not match typed Mac string ID/index"
                                )
                        if operation.get("op") == "max_chars" and node.get(
                            "type_code"
                        ) == "nmbr" and int(operation.get("value", -1)) != int(
                            family.get("max_char_count", -2)
                        ):
                            errors.append(
                                f"{case.resource.text()} node {offset}: max chars do not "
                                "match typed Mac number payload"
                            )
                        if operation.get("op") == "number_range" and node.get(
                            "type_code"
                        ) == "nmbr":
                            expected_range = [
                                int(family.get("number_value", -2)),
                                int(family.get("number_minimum", -2)),
                                int(family.get("number_maximum", -2)),
                            ]
                            if operation.get("args") != expected_range:
                                errors.append(
                                    f"{case.resource.text()} node {offset}: number range "
                                    "does not match typed Mac payload"
                                )
    if len(recipe_list) != 17:
        errors.append(
            f"factory manifest must own exactly 17 functions, found {len(recipe_list)}"
        )
    expected_windows = {
        f"0x{recipe.address:08x}"
        for recipe in recipe_list
        if recipe.emission == "resource_recipe"
    }
    if windows_recipes is not None and set(windows_recipes) != expected_windows:
        errors.append(
            f"{WINDOWS_RECIPE_PATH}: function keys do not exactly match resource_recipe "
            "manifest entries"
        )
    return sorted(set(errors))


def _hex(value: int) -> str:
    if value == 0:
        return "0"
    if 0 < value < 10:
        return str(value)
    if value < 0:
        return f"-0x{-value:x}"
    return f"0x{value:x}"


def _bool(value: object) -> str:
    return "true" if bool(value) else "false"


def _tag(value: int, text: str) -> str:
    escaped = text.replace("'", "\\'")
    return f"0x{value:08x}u /* '{escaped}' */"


def _emit_pop(lines: list[str], tag_value: int, tag_text: str, indent: str) -> None:
    del tag_value, tag_text
    lines.append(f"{indent}PopUiWidgetBuildStackNode();")


def _emit_view(lines: list[str], view: dict, indent: str = "    ") -> set[str]:
    classes: set[str] = set()
    stack: list[dict] = []
    # The compact/expanded legacy recipes predate recovery of embedded `nmbr`
    # records.  Only resource_recipe factories opt into those newly typed
    # children, so recovering the oracle does not silently reshape unrelated
    # Windows functions.
    for node in (row for row in view.get("nodes", []) if row["type_code"] != "nmbr"):
        depth = int(node["depth"])
        while len(stack) > depth:
            closed = stack.pop()
            _emit_pop(lines, int(closed["tag_value"]), str(closed["tag"]), indent)

        class_name = _resolved_class(node)
        classes.add(class_name)
        geometry = node["geometry"]

        lines.append("")
        lines.append(f"{indent}widget = new {class_name}();")
        lines.append(f"{indent}g_pUiResourceContext = widget;")
        lines.append(f"{indent}if (g_pUiResourceHead != 0) {{")
        lines.append(
            f"{indent}  parent = static_cast<TView*>(g_UiWidgetBuildStack006a13e0.GetTail());"
        )
        lines.append(f"{indent}}} else {{")
        lines.append(f"{indent}  g_pUiResourceHead = widget;")
        lines.append(f"{indent}  parent = 0;")
        lines.append(f"{indent}}}")
        lines.append(f"{indent}PushUiWidgetBuildStackNode(widget);")
        lines.append(f"{indent}offset[0] = {_hex(int(geometry['x']))};")
        lines.append(f"{indent}offset[1] = {_hex(int(geometry['y']))};")
        lines.append(f"{indent}size[0] = {_hex(int(geometry['width']))};")
        lines.append(f"{indent}size[1] = {_hex(int(geometry['height']))};")
        lines.append(
            f"{indent}widget->InitializeUiResourceEntryFrameAndParent("
            "0, parent, offset, size, 0, 0, 1);"
        )
        lines.append(
            f"{indent}widget->controlTag = static_cast<int>("
            f"{_tag(int(node['tag_value']), str(node['tag']))});"
        )
        lines.append(f"{indent}widget->controlValue3c = 0;")
        lines.append(
            f"{indent}widget->SetEnabled({_hex(int(node['enabled']))}, 0);"
        )
        lines.append(f"{indent}widget->SetState({_hex(int(node['state']))}, 0);")
        lines.append(
            f"{indent}widget->inputGateFlag4c = {_bool(node['input_gate'])};"
        )
        lines.append(
            f"{indent}widget->childHitTestFlag4d = {_bool(node['child_hit_test'])};"
        )

        family = node.get("family", {})
        family_code = str(node["type_code"])
        frame_style = family.get("frame_style")
        insets = family.get("content_insets")
        if (
            family_code in LAYOUT_FAMILIES
            and isinstance(frame_style, int)
            and 0 <= frame_style <= 0xFFFF
            and isinstance(insets, list)
            and len(insets) == 4
        ):
            args = ", ".join(_hex(int(value)) for value in insets)
            lines.append(f"{indent}{{")
            lines.append(
                f"{indent}  static_cast<TControl*>(g_pUiResourceContext)->frameStyle60 = "
                f"{_hex(frame_style)};"
            )
            lines.append(f"{indent}#pragma inline_depth(0)")
            lines.append(f"{indent}  CRect contentInsets({args});")
            lines.append(f"{indent}#pragma inline_depth()")
            for field in ("left", "top", "right", "bottom"):
                lines.append(
                    f"{indent}  static_cast<TControl*>(g_pUiResourceContext)"
                    f"->contentInsets68.{field} = contentInsets.{field};"
                )
        picture_id = family.get("picture_id")
        if family_code == "pict" and isinstance(picture_id, int):
            lines.append(
                f"{indent}  static_cast<TPicture*>(g_pUiResourceContext)"
                f"->SetPictureResourceIdAndRefresh({_hex(picture_id)}, 0);"
            )
        if (
            family_code in LAYOUT_FAMILIES
            and isinstance(frame_style, int)
            and 0 <= frame_style <= 0xFFFF
            and isinstance(insets, list)
            and len(insets) == 4
        ):
            lines.append(f"{indent}}}")
        if family_code in ("wind", "fwnd"):
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->topmostFlag70 = false;"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->resourceFlag6f = true;"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->resourceFlag6e = true;"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)"
                "->useCaptionedFrameFlag6d = false;"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->resourceFlag6c = false;"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->resourceFlag71 = true;"
            )
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->windowFlags = 8;")
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->windowStyleType = 2;"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)"
                "->GetEmbeddedDialogBehavior()->SetFlag0C(1);"
            )
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)"
                "->GetEmbeddedDialogBehavior()->SetUiColorDescriptorGoldTriplet("
                "1, 0x20202020, 0x20202020);"
            )
        lines.append(f"{indent}g_pUiResourceContext = 0;")
        stack.append(node)

    while stack:
        closed = stack.pop()
        _emit_pop(lines, int(closed["tag_value"]), str(closed["tag"]), indent)
    return classes


def _emit_view_compact(lines: list[str], view: dict, indent: str = "    ") -> set[str]:
    """Emit the helper-call shape used by compact Windows builder regions."""
    classes: set[str] = set()
    stack: list[dict] = []
    for node in (row for row in view.get("nodes", []) if row["type_code"] != "nmbr"):
        depth = int(node["depth"])
        while len(stack) > depth:
            closed = stack.pop()
            lines.append(
                f"{indent}PopUiResourcePoolNode("
                f"{_tag(int(closed['tag_value']), str(closed['tag']))});"
            )

        class_name = _resolved_class(node)
        classes.add(class_name)
        variable = f"node_{int(node['offset']):04x}"
        geometry = node["geometry"]
        parent = stack[-1] if stack else None
        parent_arg = (
            _tag(int(parent["tag_value"]), str(parent["tag"])) if parent else "0"
        )
        lines.append("")
        lines.append(f"{indent}{class_name}* {variable} = new {class_name}();")
        lines.append(
            f"{indent}RegisterUiResourceEntry("
            f"{_tag(int(node['type_value']), str(node['type_code']))}, "
            f"{_tag(int(node['tag_value']), str(node['tag']))}, {variable}, "
            f"{_hex(int(geometry['x']))}, {_hex(int(geometry['y']))}, "
            f"{_hex(int(geometry['width']))}, {_hex(int(geometry['height']))}, "
            f"{_hex(int(node['state']))}, {_hex(int(node['enabled']))}, "
            f"{parent_arg}, 0);"
        )
        lines.append(
            f"{indent}SetUiResourceStateFlags({_hex(int(node['input_gate']))}, "
            f"{_hex(int(node['child_hit_test']))});"
        )

        family = node.get("family", {})
        family_code = str(node["type_code"])
        frame_style = family.get("frame_style")
        insets = family.get("content_insets")
        if (
            family_code in LAYOUT_FAMILIES
            and isinstance(frame_style, int)
            and 0 <= frame_style <= 0xFFFF
            and isinstance(insets, list)
            and len(insets) == 4
        ):
            args = ", ".join(_hex(int(value)) for value in insets)
            lines.append(
                f"{indent}SetUiResourceLayoutValues({_hex(frame_style)}, {args});"
            )
        picture_id = family.get("picture_id")
        if family_code == "pict" and isinstance(picture_id, int):
            lines.append(f"{indent}SetUiResourceContextPictureId({_hex(picture_id)});")
        if family_code in ("wind", "fwnd"):
            lines.append(
                f"{indent}SetUiResourceContextFlagsAndMetrics(8, 2, 0, 1, 1, 0, 0, 1);"
            )
            lines.append(
                f"{indent}ApplyUiResourceColorTripletFromContext("
                "1, 1, 0x20202020, 0x20202020);"
            )
        lines.append(f"{indent}ClearUiResourceContext();")
        stack.append(node)

    while stack:
        closed = stack.pop()
        lines.append(
            f"{indent}PopUiResourcePoolNode("
            f"{_tag(int(closed['tag_value']), str(closed['tag']))});"
        )
    return classes


def _cpp_value(value: object) -> str:
    if isinstance(value, int):
        return _hex(value)
    return str(value)


def _cpp_args(values: Iterable[object]) -> str:
    return ", ".join(_cpp_value(value) for value in values)


def _emit_recipe_layout(
    lines: list[str], node: dict, row: dict, variable: str, indent: str
) -> None:
    family = node.get("family", {})
    family_code = str(node["type_code"])
    layout_values = row.get("layout_values")
    frame_style = (
        layout_values[0] if isinstance(layout_values, list) and len(layout_values) == 5
        else family.get("frame_style")
    )
    insets = (
        layout_values[1:] if isinstance(layout_values, list) and len(layout_values) == 5
        else family.get("content_insets")
    )
    if not (
        family_code in LAYOUT_FAMILIES
        and isinstance(frame_style, int)
        and 0 <= frame_style <= 0xFFFF
        and isinstance(insets, list)
        and len(insets) == 4
    ):
        return
    if row["emission"] == "compact":
        lines.append(
            f"{indent}SetUiResourceLayoutValues({_hex(frame_style)}, "
            f"{_cpp_args(int(value) for value in insets)});"
        )
        return
    target = (
        f"static_cast<TControl*>(g_pUiResourceContext)"
        if row.get("layout") == "pragma"
        else variable
    )
    lines.append(f"{indent}{target}->frameStyle60 = {_hex(frame_style)};")
    if row.get("layout") == "pragma":
        lines.append(f"{indent}#pragma inline_depth(0)")
    lines.append(f"{indent}CRect contentInsets({_cpp_args(int(value) for value in insets)});")
    if row.get("layout") == "pragma":
        lines.append(f"{indent}#pragma inline_depth()")
    for field in ("left", "top", "right", "bottom"):
        lines.append(
            f"{indent}{target}->contentInsets68.{field} = contentInsets.{field};"
        )


def _emit_style_pair(
    lines: list[str], operation: dict, variable: str, indent: str
) -> None:
    if operation["mode"] == "helper":
        lines.append(
            f"{indent}ReplaceUiResourceContextPairBuffer("
            f"{_cpp_args(operation['args'])});"
        )
        return
    lines.append(f"{indent}delete {variable}->stylePayload48;")
    if operation["mode"] == "operator_new_reset":
        lines.append(
            f"{indent}{variable}->stylePayload48 = "
            "static_cast<TUiStyleBytes*>(operator new(8));"
        )
        lines.append(f"{indent}if ({variable}->stylePayload48 != 0) {{")
        lines.append(f"{indent}  {variable}->stylePayload48->Reset();")
        lines.append(f"{indent}}}")
    else:
        lines.append(f"{indent}{variable}->stylePayload48 = new TUiStyleBytes();")
    lines.append(
        f"{indent}{variable}->stylePayload48->styleWord = "
        f"{_cpp_value(operation['style_word'])};"
    )
    lines.append(
        f"{indent}{variable}->stylePayload48->packedColor = "
        f"{_cpp_value(operation['packed_color'])};"
    )


def _emit_window_direct(lines: list[str], variable: str, indent: str) -> None:
    target = variable if variable != "widget" else "static_cast<TWindow*>(g_pUiResourceContext)"
    for field, value in (
        ("topmostFlag70", 0),
        ("resourceFlag6f", 1),
        ("resourceFlag6e", 1),
        ("useCaptionedFrameFlag6d", 0),
        ("resourceFlag6c", 0),
        ("resourceFlag71", 1),
    ):
        lines.append(f"{indent}{target}->{field} = {_bool(value)};")
    lines.append(f"{indent}{target}->windowFlags = 0x8;")
    lines.append(f"{indent}{target}->windowStyleType = 0x2;")
    lines.append(f"{indent}{target}->GetEmbeddedDialogBehavior()->SetFlag0C(1);")
    lines.append(
        f"{indent}{target}->GetEmbeddedDialogBehavior()"
        "->SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);"
    )


def _emit_recipe_operations(
    lines: list[str], node: dict, row: dict, variable: str, indent: str
) -> None:
    operations = row.get("operations", [])
    for operation in operations:
        if operation["op"] == "style_pair":
            _emit_style_pair(lines, operation, variable, indent)
    scoped_layout = row.get("layout") == "pragma"
    operation_indent = indent
    if scoped_layout:
        lines.append(f"{indent}{{")
        operation_indent += "  "
    _emit_recipe_layout(lines, node, row, variable, operation_indent)
    picture_id = node.get("family", {}).get("picture_id")
    if node.get("type_code") == "pict" and isinstance(picture_id, int):
        picture_mode = row.get("picture")
        if picture_mode == "helper":
            lines.append(
                f"{operation_indent}SetUiResourceContextPictureId({_hex(picture_id)});"
            )
        elif picture_mode == "context" or variable == "widget":
            lines.append(
                f"{operation_indent}static_cast<TPicture*>(g_pUiResourceContext)"
                f"->SetPictureResourceIdAndRefresh({_hex(picture_id)}, 0);"
            )
        elif picture_mode == "variable":
            lines.append(
                f"{operation_indent}{variable}->SetPictureResourceIdAndRefresh("
                f"{_hex(picture_id)}, 0);"
            )
    for operation in operations:
        op = operation["op"]
        if op == "style_pair":
            continue
        if op == "text_binding":
            lines.append(
                f"{operation_indent}BindUiResourceTextAndStyle("
                f"{_cpp_args(operation['args'])});"
            )
        elif op == "max_chars":
            lines.append(
                f"{operation_indent}SetUiResourceContextMaxCharCount("
                f"{_cpp_value(operation['value'])});"
            )
        elif op == "number_range":
            lines.append(
                f"{operation_indent}SetUiResourceContextNumberValueAndRange("
                f"{_cpp_args(operation['args'])});"
            )
        elif op == "cluster_code":
            if operation["mode"] == "helper":
                lines.append(
                    f"{operation_indent}SetUiResourceContextStringCode("
                    f"{_cpp_value(operation['value'])});"
                )
            else:
                target = (
                    variable
                    if row["emission"] == "expanded" and variable != "widget"
                    else "static_cast<TCluster*>(g_pUiResourceContext)"
                )
                lines.append(
                    f"{operation_indent}{target}->selectedChildTag = {_cpp_value(operation['value'])};"
                )
        elif op == "window":
            if operation["mode"] == "helper":
                if operation.get("metrics") is not None:
                    lines.append(
                        f"{operation_indent}SetUiResourceContextFlagsAndMetrics("
                        f"{_cpp_args(operation['metrics'])});"
                    )
                if operation.get("color") is not None:
                    lines.append(
                        f"{operation_indent}ApplyUiResourceColorTripletFromContext("
                        f"{_cpp_args(operation['color'])});"
                    )
            else:
                _emit_window_direct(lines, variable, operation_indent)
        elif op == "edit_validation":
            lines.append(f"{operation_indent}{variable}->AssertValid();")
            lines.append(
                f"{operation_indent}{variable}->maxCharacterCount = "
                f"{_cpp_value(operation['max_chars'])};"
            )
    if scoped_layout:
        lines.append(f"{indent}}}")


def _emit_recipe_node(
    lines: list[str], node: dict, row: dict, parent_node: dict | None, indent: str
) -> tuple[str, str]:
    class_name = str(row.get("class") or _resolved_class(node))
    geometry = node["geometry"]
    variable = str(row.get("variable") or f"node_{int(node['offset']):04x}")
    lines.append("")
    scoped_node = row.get("allocation") != "shared"
    if scoped_node:
        lines.append(f"{indent}{{")
    inner = indent + "  " if scoped_node else indent
    if row["emission"] == "compact":
        if row.get("allocation") == "shared":
            variable = "widget"
            lines.append(f"{inner}widget = new {class_name}();")
        else:
            lines.append(f"{inner}{class_name}* {variable} = new {class_name}();")
        parent_arg = (
            _tag(int(parent_node["tag_value"]), str(parent_node["tag"]))
            if parent_node is not None
            else "0"
        )
        lines.append(
            f"{inner}RegisterUiResourceEntry("
            f"{_tag(int(node['type_value']), str(node['type_code']))}, "
            f"{_tag(int(node['tag_value']), str(node['tag']))}, {variable}, "
            f"{_hex(int(geometry['x']))}, {_hex(int(geometry['y']))}, "
            f"{_hex(int(geometry['width']))}, {_hex(int(geometry['height']))}, "
            f"{_hex(int(node['state']))}, {_hex(int(node['enabled']))}, "
            f"{parent_arg}, "
            f"{_hex(int(node['control_value'])) if row.get('control_value') == 'resource' else '0'});"
        )
        if row.get("state") == "helper":
            lines.append(
                f"{inner}SetUiResourceStateFlags({_hex(int(node['input_gate']))}, "
                f"{_hex(int(node['child_hit_test']))});"
            )
        else:
            lines.append(
                f"{inner}static_cast<TControl*>(g_pUiResourceContext)"
                f"->inputGateFlag4c = {_bool(node['input_gate'])};"
            )
            lines.append(
                f"{inner}static_cast<TControl*>(g_pUiResourceContext)"
                f"->childHitTestFlag4d = {_bool(node['child_hit_test'])};"
            )
    else:
        if row.get("allocation") == "shared":
            variable = "widget"
            lines.append(f"{inner}widget = new {class_name}();")
        else:
            lines.append(f"{inner}{class_name}* {variable} = new {class_name}();")
        lines.append(f"{inner}g_pUiResourceContext = {variable};")
        lines.append(f"{inner}if (g_pUiResourceHead != 0) {{")
        lines.append(
            f"{inner}  parent = static_cast<TView*>("
            "g_UiWidgetBuildStack006a13e0.GetTail());"
        )
        lines.append(f"{inner}}} else {{")
        lines.append(f"{inner}  g_pUiResourceHead = {variable};")
        lines.append(f"{inner}  parent = 0;")
        lines.append(f"{inner}}}")
        lines.append(f"{inner}PushUiWidgetBuildStackNode({variable});")
        lines.append(f"{inner}offset[0] = {_hex(int(geometry['x']))};")
        lines.append(f"{inner}offset[1] = {_hex(int(geometry['y']))};")
        lines.append(f"{inner}size[0] = {_hex(int(geometry['width']))};")
        lines.append(f"{inner}size[1] = {_hex(int(geometry['height']))};")
        lines.append(
            f"{inner}{variable}->InitializeUiResourceEntryFrameAndParent("
            "0, parent, offset, size, 0, 0, 1);"
        )
        lines.append(
            f"{inner}{variable}->controlTag = static_cast<int>("
            f"{_tag(int(node['tag_value']), str(node['tag']))});"
        )
        control_value = (
            _hex(int(node["control_value"]))
            if row.get("control_value") == "resource"
            else "0"
        )
        lines.append(f"{inner}{variable}->controlValue3c = {control_value};")
        lines.append(
            f"{inner}{variable}->SetEnabled({_hex(int(node['enabled']))}, 0);"
        )
        lines.append(
            f"{inner}{variable}->SetState({_hex(int(node['state']))}, 0);"
        )
        flag_target = (
            "g_pUiResourceContext" if row.get("flags") == "context" else variable
        )
        lines.append(
            f"{inner}{flag_target}->inputGateFlag4c = {_bool(node['input_gate'])};"
        )
        lines.append(
            f"{inner}{flag_target}->childHitTestFlag4d = {_bool(node['child_hit_test'])};"
        )
    _emit_recipe_operations(lines, node, row, variable, inner)
    if row.get("clear") == "helper":
        lines.append(f"{inner}ClearUiResourceContext();")
    elif row.get("clear") == "direct":
        lines.append(f"{inner}g_pUiResourceContext = 0;")
    if scoped_node:
        lines.append(f"{indent}}}")
    return class_name, variable


def render_resource_recipe(
    recipe: UiFactoryRecipe,
    views: dict[UiResourceKey, dict],
    windows_recipes: dict[str, dict],
    annotation_kind: str = "FUNCTION",
) -> str:
    windows_function = windows_recipes[f"0x{recipe.address:08x}"]
    cases_by_event = {case.event: case for case in recipe.cases}
    ordered_cases = (
        [cases_by_event[int(value, 0)] for value in windows_function["case_order"]]
        if len(recipe.cases) > 1
        else list(recipe.cases)
    )
    needs_shared_widget = any(
        node_row.get("allocation") == "shared"
        for case_row in windows_function["cases"].values()
        for node_row in case_row.get("nodes", {}).values()
    )
    body: list[str] = []
    classes: set[str] = set()
    if annotation_kind != "none":
        body.append(f"// {annotation_kind}: IMPERIALISM 0x{recipe.address:08x}")
    body.append(recipe.prototype + " {")
    body.append("  TView* parent;")
    if needs_shared_widget:
        body.append("  TView* widget;")
    body.extend(("  int offset[2];", "  int size[2];", ""))
    body.append("  g_pUiResourceHead = 0;")
    if len(recipe.cases) == 1:
        body.append(
            f"  if (static_cast<short>(nEventCode) != {_hex(recipe.cases[0].event)}) {{"
        )
        body.extend(("    return 0;", "  }"))
    else:
        body.append(
            f"  switch (static_cast<{windows_function['switch_type']}>(nEventCode)) {{"
        )

    for case in ordered_cases:
        case_indent = "  " if len(recipe.cases) == 1 else "    "
        if len(recipe.cases) != 1:
            body.append(f"  case {_hex(case.event)}: {{")
        if case.resource is None:
            body.append(
                f"{case_indent}// WINDOWS_ONLY: resource absent; binary evidence {case.evidence}."
            )
        else:
            view = views[case.resource]
            case_recipe = windows_function["cases"][f"0x{case.event:04x}"]
            skipped = set(case_recipe.get("skip_offsets", []))
            nodes_by_offset = {
                int(node["offset"]): node for node in view.get("nodes", [])
            }
            emitted = {
                offset: node
                for offset, node in nodes_by_offset.items()
                if f"0x{offset:04x}" not in skipped
            }

            def emitted_parent(node: dict) -> dict | None:
                parent_offset = node.get("parent_offset")
                while parent_offset is not None and int(parent_offset) not in emitted:
                    parent_offset = nodes_by_offset[int(parent_offset)].get("parent_offset")
                return emitted.get(int(parent_offset)) if parent_offset is not None else None

            stack: list[dict] = []
            for node in view.get("nodes", []):
                offset = f"0x{int(node['offset']):04x}"
                if offset in skipped:
                    continue
                row = case_recipe["nodes"][offset]
                class_name, _ = _emit_recipe_node(
                    body, node, row, emitted_parent(node), case_indent
                )
                classes.add(class_name)
                stack.append(node)
                for pop_mode in row.get("pops", []):
                    if not stack:
                        raise ValueError(
                            f"0x{recipe.address:08x}/0x{case.event:x}/{offset}: "
                            "Windows pop recipe underflows"
                        )
                    closed = stack.pop()
                    if pop_mode == "pool":
                        body.append(
                            f"{case_indent}PopUiResourcePoolNode("
                            f"{_tag(int(closed['tag_value']), str(closed['tag']))});"
                        )
                    else:
                        body.append(f"{case_indent}PopUiWidgetBuildStackNode();")
        if len(recipe.cases) != 1:
            body.append("  } break;")
    if len(recipe.cases) != 1:
        body.extend(("  default:", "    return 0;", "  }"))
    body.extend(
        (
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
        '#include "game/global_data_tables.h"',
        '#include "game/turn_event_dialog_builder_detail.h"',
        '#include "game/ui_resource_builder.h"',
    ]
    for class_name in sorted(classes):
        if class_name != "TView":
            includes.append(f'#include "game/{class_name}.h"')
    return "// AUTOGENERATED FROM RESOURCE AND WINDOWS RECIPES. DO NOT EDIT.\n" + "\n".join(includes) + "\n\n" + "\n".join(body) + "\n"


def render_factory(
    recipe: UiFactoryRecipe,
    views: dict[UiResourceKey, dict],
    annotation_kind: str = "FUNCTION",
) -> str:
    if recipe.emission == "resource_recipe":
        raise ValueError("resource recipes require render_resource_recipe()")
    emit_view = _emit_view_compact if recipe.emission == "compact" else _emit_view
    body: list[str] = []
    classes: set[str] = set()
    if annotation_kind != "none":
        body.append(f"// {annotation_kind}: IMPERIALISM 0x{recipe.address:08x}")
    body.append(recipe.prototype + " {")
    if recipe.emission == "expanded":
        body.append("  TView* parent;")
        body.append("  TView* widget;")
        body.append("  int offset[2];")
        body.append("  int size[2];")
        body.append("")
    body.append("  g_pUiResourceHead = 0;")
    if len(recipe.cases) == 1:
        body.append(
            f"  if (static_cast<short>(nEventCode) != {_hex(recipe.cases[0].event)}) {{"
        )
        body.append("    return 0;")
        body.append("  }")
        case = recipe.cases[0]
        if case.resource is not None:
            classes.update(emit_view(body, views[case.resource], indent="  "))
    else:
        body.append("  switch (static_cast<unsigned short>(nEventCode)) {")
        for case in recipe.cases:
            body.append(f"  case {_hex(case.event)}: {{")
            if case.resource is not None:
                classes.update(emit_view(body, views[case.resource], indent="    "))
            else:
                body.append(
                    f"    // WINDOWS_ONLY: resource absent; binary evidence {case.evidence}."
                )
            body.append("    break;")
            body.append("  }")
        body.append("  default:")
        body.append("    return 0;")
        body.append("  }")
    body.append("")
    body.append("  if (g_pUiResourceHead != 0) {")
    body.append("    g_pUiResourceHead->PropagateUiResourceContextRecursive(pHostWindow);")
    body.append("  }")
    body.append("  return g_pUiResourceHead;")
    body.append("}")

    includes = [
        '#include "game/turn_event_dialog_factory.h"',
        '#include "game/global_data_tables.h"',
        '#include "game/turn_event_dialog_builder_detail.h"',
        '#include "game/ui_resource_builder.h"',
    ]
    for class_name in sorted(classes):
        if class_name != "TView":
            includes.append(f'#include "game/{class_name}.h"')
    return "// AUTOGENERATED FILE. DO NOT EDIT.\n" + "\n".join(includes) + "\n\n" + "\n".join(body) + "\n"


def write_generated(
    repo_root: Path,
    output_dir: Path,
    recipes: list[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
    windows_recipes: dict[str, dict],
    annotation_kind: str = "FUNCTION",
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    expected = {recipe.output_name for recipe in recipes}
    for stale in output_dir.glob("*.cpp"):
        if stale.name not in expected:
            stale.unlink()
    files = []
    for recipe in recipes:
        output = output_dir / recipe.output_name
        generated_text = (
            render_resource_recipe(recipe, views, windows_recipes, annotation_kind)
            if recipe.emission == "resource_recipe"
            else render_factory(recipe, views, annotation_kind)
        )
        if not output.is_file() or output.read_text(encoding="utf-8") != generated_text:
            output.write_text(generated_text, encoding="utf-8")
        files.append(
            {
                "address": f"0x{recipe.address:08x}",
                "name": recipe.name,
                "file": recipe.output_name,
                "sha256": hashlib.sha256(generated_text.encode("utf-8")).hexdigest(),
                "resources": [
                    case.resource.text() for case in recipe.cases if case.resource is not None
                ],
                "emission": recipe.emission,
            }
        )
    manifest = {
        "format_version": FORMAT_VERSION,
        "recipe_sha256": _sha256(repo_root / MANIFEST_PATH),
        "resource_ir_sha256": _sha256(repo_root / IR_PATH),
        "windows_recipe_sha256": _sha256(repo_root / WINDOWS_RECIPE_PATH),
        "annotation_kind": annotation_kind,
        "files": files,
    }
    manifest_path = output_dir / "_manifest.json"
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if not manifest_path.is_file() or manifest_path.read_text(encoding="utf-8") != manifest_text:
        manifest_path.write_text(manifest_text, encoding="utf-8")
    return manifest


def generated_claim_rows(repo_root: Path) -> list[dict[str, object]]:
    """Committed generated ownership rows consumed by tools.source_model."""
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gen-dir", default="build-msvc500/generated/ui")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--function")
    parser.add_argument("--view")
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=1)
    recipes = load_recipes(repo_root)
    views = load_ui_views(repo_root)
    windows_recipes = load_windows_recipes(repo_root)
    errors = validate(repo_root, recipes, views, windows_recipes)
    if errors:
        print("UI codegen validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1
    if args.view:
        key = UiResourceKey.parse(args.view)
        print(json.dumps(views[key], indent=2, sort_keys=True))
        return 0
    if args.function:
        address = int(args.function, 16)
        recipes = [recipe for recipe in recipes if recipe.address == address]
        if not recipes:
            print(f"No generated UI factory at 0x{address:08x}")
            return 2
    if args.check:
        print(
            f"UI codegen check passed: {len(recipes)} functions, "
            f"{sum(len(recipe.cases) for recipe in recipes)} cases"
        )
        return 0
    output_dir = resolve_repo_path(repo_root, args.gen_dir)
    manifest = write_generated(repo_root, output_dir, recipes, views, windows_recipes)
    print(f"Wrote {len(manifest['files'])} UI factory TUs to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
