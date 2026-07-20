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
PROFILE_DIR = "config/ui_codegen_profiles"
FORMAT_VERSION = 1
EMISSION_MODES = frozenset(("expanded", "compact", "windows_profile"))

DEFAULT_CLASSES = {
    "view": "TView",
    "pict": "TPicture",
    "cntl": "TControl",
    "stat": "TStaticText",
    "clus": "TCluster",
    "tevw": "TTEView",
    "edit": "TEditText",
    "wind": "TWindow",
    "fwnd": "TFloatWindow",
}

# Cross-platform spelling differences that are independently represented by a
# real Windows class.  This is a naming bridge only; it assigns no inheritance.
CLASS_ALIASES = {
    "TToolbarCluster": "TToolBarCluster",
    "TMyWindow": "TWindow",
}

LAYOUT_FAMILIES = frozenset(("pict", "cntl", "stat", "clus", "edit"))


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


def _resolved_class(node: dict) -> str:
    class_name = str(node.get("class_name") or "")
    if class_name:
        return CLASS_ALIASES.get(class_name, class_name)
    try:
        return DEFAULT_CLASSES[str(node["type_code"])]
    except KeyError as exc:
        raise ValueError(f"no Windows default class for {node.get('type_code')!r}") from exc


def validate(repo_root: Path, recipes: Iterable[UiFactoryRecipe], views: dict) -> list[str]:
    recipe_list = list(recipes)
    errors: list[str] = []
    include_dir = repo_root / "include" / "game"
    referenced: set[UiResourceKey] = set()
    for recipe in recipe_list:
        if recipe.emission == "windows_profile":
            profile = repo_root / PROFILE_DIR / f"{recipe.output_name}.in"
            if not profile.is_file():
                errors.append(
                    f"0x{recipe.address:08x}: missing Windows emission profile {profile}"
                )
            else:
                profile_text = profile.read_text(encoding="utf-8")
                marker = f"// FUNCTION: IMPERIALISM 0x{recipe.address:08x}"
                if marker not in profile_text:
                    errors.append(f"{profile}: missing {marker}")
                if recipe.prototype not in profile_text:
                    errors.append(f"{profile}: prototype does not match manifest")
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
    if len(recipe_list) != 17:
        errors.append(
            f"factory manifest must own exactly 17 functions, found {len(recipe_list)}"
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


def _tag(value: int, text: str) -> str:
    escaped = text.replace("'", "\\'")
    return f"0x{value:08x}u /* '{escaped}' */"


def _emit_pop(lines: list[str], tag_value: int, tag_text: str, indent: str) -> None:
    del tag_value, tag_text
    lines.append(f"{indent}PopUiWidgetBuildStackNode();")


def _emit_view(lines: list[str], view: dict, indent: str = "    ") -> set[str]:
    classes: set[str] = set()
    stack: list[dict] = []
    for node in view.get("nodes", []):
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
            f"{indent}widget->inputGateFlag4c = {_hex(int(node['input_gate']))};"
        )
        lines.append(
            f"{indent}widget->childHitTestFlag4d = {_hex(int(node['child_hit_test']))};"
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
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->topmostFlag70 = 0;")
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->flag6f = 1;")
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->flag6e = 1;")
            lines.append(
                f"{indent}static_cast<TWindow*>(g_pUiResourceContext)"
                "->useCaptionedFrameFlag6d = 0;"
            )
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->flag6c = 0;")
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->flag71 = 1;")
            lines.append(f"{indent}static_cast<TWindow*>(g_pUiResourceContext)->field9c = 8;")
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
    for node in view.get("nodes", []):
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


def render_factory(
    recipe: UiFactoryRecipe,
    views: dict[UiResourceKey, dict],
    annotation_kind: str = "FUNCTION",
) -> str:
    if recipe.emission == "windows_profile":
        raise ValueError("Windows profiles require render_windows_profile()")
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


def render_windows_profile(
    repo_root: Path, recipe: UiFactoryRecipe, annotation_kind: str = "FUNCTION"
) -> str:
    profile = repo_root / PROFILE_DIR / f"{recipe.output_name}.in"
    profile_text = profile.read_text(encoding="utf-8")
    marker = f"// FUNCTION: IMPERIALISM 0x{recipe.address:08x}"
    if annotation_kind == "none":
        profile_text = profile_text.replace(marker + "\n", "")
    elif annotation_kind != "FUNCTION":
        profile_text = profile_text.replace(
            marker, f"// {annotation_kind}: IMPERIALISM 0x{recipe.address:08x}"
        )
    return "// AUTOGENERATED FROM A WINDOWS EMISSION PROFILE. DO NOT EDIT.\n" + profile_text


def write_generated(
    repo_root: Path,
    output_dir: Path,
    recipes: list[UiFactoryRecipe],
    views: dict[UiResourceKey, dict],
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
            render_windows_profile(repo_root, recipe, annotation_kind)
            if recipe.emission == "windows_profile"
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
                "profile_sha256": (
                    _sha256(repo_root / PROFILE_DIR / f"{recipe.output_name}.in")
                    if recipe.emission == "windows_profile"
                    else None
                ),
            }
        )
    manifest = {
        "format_version": FORMAT_VERSION,
        "recipe_sha256": _sha256(repo_root / MANIFEST_PATH),
        "resource_ir_sha256": _sha256(repo_root / IR_PATH),
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
    errors = validate(repo_root, recipes, views)
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
    manifest = write_generated(repo_root, output_dir, recipes, views)
    print(f"Wrote {len(manifest['files'])} UI factory TUs to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
