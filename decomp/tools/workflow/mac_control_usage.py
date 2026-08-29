#!/usr/bin/env python3
"""Build Mac View control-class/tag semantic hints for porting.

The index is a cross-platform naming and structure oracle.  It deliberately
does not claim Windows addresses, calling conventions, vtable slots, or
inheritance from Mac resource evidence.
"""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
from typing import Iterable

from tools.common.file_scan import iter_files
from tools.common.symbols import names_by_address
from tools.ui_cpp_codegen import IR_PATH, load_recipes, load_ui_views


TEXT_RESOURCES_PATH = "vendor/macos_codewarrior/evidence/resources/text_resources.json"

TYPE_FAMILY_CLASSES = {
    "clus": "TCluster",
    "cntl": "TControl",
    "edit": "TEditText",
    "fwnd": "TFloatWindow",
    "nmbr": "TNumberText",
    "radb": "TRadioPictureButton",
    "chkb": "TCzechBox",
    "pict": "TPicture",
    "stat": "TStaticText",
    "tevw": "TTEView",
    "view": "TView",
    "wind": "TWindow",
}

_FUNCTION_RE = re.compile(r"^// FUNCTION: IMPERIALISM (0x[0-9a-fA-F]+)$", re.MULTILINE)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_PATH_RE = re.compile(r"^[A-Za-z]:\\Ambit\\(?:Cross\\)?U[^\\]+\.cpp$", re.IGNORECASE)
_PATH_DEFINITION_RE = re.compile(
    r"\b(?P<symbol>[A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*=\s*(?P<literal>\"(?:\\.|[^\"\\])*\")"
)


def _node_id(screen: str, offset: int) -> str:
    return f"{screen}@0x{offset:04x}"


def _typed_family(node: dict) -> dict:
    family = node.get("family")
    if not isinstance(family, dict):
        return {}
    return {key: value for key, value in family.items() if key != "raw_hex"}


def _decoded_style_summary(
    text_styles: dict[tuple[str, int], dict], resource: str
) -> dict | None:
    resource_file, resource_id = resource.rsplit(":TxSt:", 1)
    style = text_styles.get((resource_file, int(resource_id)))
    if style is None:
        return None
    return {
        name: style[name]
        for name in (
            "font_name",
            "point_size",
            "face_flags",
            "face_flag_names",
            "foreground_color",
            "decoder_confidence",
        )
    }


def _effective_class(node: dict) -> tuple[str, str]:
    declared = str(node.get("class_name", "")).strip()
    if declared:
        return declared, "declared"
    type_code = str(node.get("type_code", ""))
    return TYPE_FAMILY_CLASSES.get(type_code, f"<{type_code or 'unknown'}>"), "type_family"


def _decode_literal(token: str) -> str | None:
    try:
        value = ast.literal_eval(token)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _source_module_evidence(repo_root: Path) -> dict:
    """Recover direct Windows source-module facts and qualified class owners."""
    definitions: dict[str, dict] = {}
    source_paths = list(iter_files([str(repo_root / "src" / "game")], patterns=("*.cpp",)))
    for path in source_paths:
        source = path.read_text(encoding="utf-8", errors="replace")
        for match in _PATH_DEFINITION_RE.finditer(source):
            value = _decode_literal(match.group("literal"))
            if value is None or not _PATH_RE.fullmatch(value):
                continue
            definitions[match.group("symbol")] = {
                "path": value,
                "module": value.rsplit("\\", 1)[-1],
                "definition_source": path.relative_to(repo_root).as_posix(),
            }

    names = names_by_address(repo_root)
    functions: dict[str, dict] = {}
    class_modules: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    module_functions: dict[str, set[str]] = defaultdict(set)
    for path in source_paths:
        source = path.read_text(encoding="utf-8", errors="replace")
        markers = list(_FUNCTION_RE.finditer(source))
        for index, marker in enumerate(markers):
            end = markers[index + 1].start() if index + 1 < len(markers) else len(source)
            body = source[marker.end() : end]
            address_value = int(marker.group(1), 0)
            address = f"0x{address_value:08x}"
            evidence: dict[str, list[dict]] = defaultdict(list)
            for symbol, definition in definitions.items():
                occurrences = len(re.findall(rf"\b{re.escape(symbol)}\b", body))
                defined_here = bool(
                    re.search(
                        rf"\b{re.escape(symbol)}\s*(?:\[[^]]*\])?\s*=",
                        body,
                    )
                )
                if occurrences <= int(defined_here):
                    continue
                evidence[definition["module"]].append(
                    {
                        "kind": "source_path_global_reference",
                        "path": definition["path"],
                        "symbol": symbol,
                        "definition_source": definition["definition_source"],
                    }
                )
            for token in _STRING_RE.findall(body):
                value = _decode_literal(token)
                if value is None or not _PATH_RE.fullmatch(value):
                    continue
                if re.search(
                    rf"\b[A-Za-z_]\w*\s*(?:\[[^]]*\])?\s*=\s*{re.escape(token)}", body
                ):
                    continue
                evidence[value.rsplit("\\", 1)[-1]].append(
                    {"kind": "inline_source_path_literal", "path": value}
                )
            if not evidence:
                continue
            name = names.get(address_value, "")
            owner = name.split("::", 1)[0] if "::" in name else ""
            if not re.fullmatch(r"[A-Za-z_]\w*", owner):
                owner = ""
            functions[address] = {
                "name": name,
                "recovered_source": path.relative_to(repo_root).as_posix(),
                "owner_class": owner or None,
                "modules": [
                    {"module": module, "status": "confirmed", "evidence": rows}
                    for module, rows in sorted(evidence.items())
                ],
            }
            for module in evidence:
                module_functions[module].add(address)
                if owner:
                    class_modules[owner][module].add(address)

    classes = {
        class_name: [
            {
                "module": module,
                "status": "confirmed",
                "functions": sorted(addresses),
            }
            for module, addresses in sorted(modules.items())
        ]
        for class_name, modules in sorted(class_modules.items())
    }
    modules = {
        module: {
            "functions": sorted(addresses),
            "classes": sorted(
                class_name for class_name, entries in classes.items() if any(
                    entry["module"] == module for entry in entries
                )
            ),
        }
        for module, addresses in sorted(module_functions.items())
    }
    return {"modules": modules, "functions": dict(sorted(functions.items())), "classes": classes}


def build_index(repo_root: Path) -> dict:
    ir_data = json.loads((repo_root / IR_PATH).read_text(encoding="utf-8"))
    views = load_ui_views(repo_root)
    nodes: list[dict] = []
    screens: dict[str, dict] = {}
    class_nodes: dict[str, list[str]] = defaultdict(list)
    tag_nodes: dict[str, list[str]] = defaultdict(list)
    text_resource_evidence = json.loads(
        (repo_root / TEXT_RESOURCES_PATH).read_text(encoding="utf-8")
    )
    text_styles = {
        (str(row["resource_file"]), int(row["resource_id"])): row
        for row in text_resource_evidence["text_styles"]
    }

    for key, view in sorted(views.items(), key=lambda item: item[0].text()):
        screen = key.text()
        source_nodes = sorted(view.get("nodes", []), key=lambda node: int(node["offset"]))
        by_offset = {int(node["offset"]): node for node in source_nodes}
        children_by_offset: dict[int, list[int]] = defaultdict(list)
        for node in source_nodes:
            parent_offset = node.get("parent_offset")
            if parent_offset is not None:
                children_by_offset[int(parent_offset)].append(int(node["offset"]))

        screen_node_ids: list[str] = []
        for node in source_nodes:
            offset = int(node["offset"])
            node_id = _node_id(screen, offset)
            screen_node_ids.append(node_id)
            class_name, class_source = _effective_class(node)
            parent_offset = node.get("parent_offset")
            parent = by_offset.get(int(parent_offset)) if parent_offset is not None else None
            parent_class, _ = _effective_class(parent) if parent is not None else ("", "")
            tag = str(node.get("tag", ""))
            family = _typed_family(node)
            style_id = family.get("text_style_id")
            if isinstance(style_id, int):
                style = text_styles.get((key.resource_file, style_id))
                family["text_style_resource"] = (
                    f"{key.resource_file}:TxSt:{style_id}"
                )
                if style is None:
                    family["text_style_resolution"] = "missing_in_file_scope"
                else:
                    family["text_style_resolution"] = "resolved"
            record = {
                "id": node_id,
                "screen": screen,
                "screen_name": str(view.get("view_name", "")),
                "offset": offset,
                "depth": int(node.get("depth", 0)),
                "tag": tag,
                "tag_value": int(node.get("tag_value", 0)),
                "type_code": str(node.get("type_code", "")),
                "class": class_name,
                "class_source": class_source,
                "declared_class": str(node.get("class_name", "")),
                "parent": (
                    _node_id(screen, int(parent_offset)) if parent_offset is not None else None
                ),
                "parent_tag": str(parent.get("tag", "")) if parent is not None else "",
                "parent_class": parent_class,
                "children": [
                    _node_id(screen, child_offset)
                    for child_offset in sorted(children_by_offset.get(offset, []))
                ],
                "geometry": dict(node.get("geometry", {})),
                "state": int(node.get("state", 0)),
                "enabled": int(node.get("enabled", 0)),
                "input_gate": int(node.get("input_gate", 0)),
                "child_hit_test": int(node.get("child_hit_test", 0)),
                "control_value": int(node.get("control_value", 0)),
                "family": family,
            }
            nodes.append(record)
            class_nodes[class_name].append(node_id)
            tag_nodes[tag].append(node_id)

        screens[screen] = {
            "name": str(view.get("view_name", "")),
            "node_count": len(source_nodes),
            "nodes": screen_node_ids,
        }

    node_by_id = {node["id"]: node for node in nodes}
    classes: dict[str, dict] = {}
    for class_name, ids in sorted(class_nodes.items()):
        instances = [node_by_id[node_id] for node_id in ids]
        classes[class_name] = {
            "instance_count": len(ids),
            "declared_instance_count": sum(
                node["class_source"] == "declared" for node in instances
            ),
            "screens": sorted({node["screen"] for node in instances}),
            "tags": dict(sorted(Counter(node["tag"] for node in instances).items())),
            "parent_classes": dict(
                sorted(Counter(node["parent_class"] for node in instances if node["parent"]).items())
            ),
            "text_styles": [
                {
                    "resource": resource,
                    "instance_count": count,
                    "decoded": _decoded_style_summary(text_styles, resource),
                }
                for resource, count in sorted(
                    Counter(
                        str(node["family"]["text_style_resource"])
                        for node in instances
                        if "text_style_resource" in node["family"]
                    ).items()
                )
            ],
            "child_classes": dict(
                sorted(
                    Counter(
                        node_by_id[child_id]["class"]
                        for node in instances
                        for child_id in node["children"]
                    ).items()
                )
            ),
            "nodes": ids,
        }

    source_modules = _source_module_evidence(repo_root)
    for class_name, entry in classes.items():
        entry["original_modules"] = source_modules["classes"].get(class_name, [])

    for screen, entry in screens.items():
        screen_classes = sorted({node_by_id[node_id]["class"] for node_id in entry["nodes"]})
        candidates: dict[str, set[str]] = defaultdict(set)
        for class_name in screen_classes:
            for association in classes[class_name]["original_modules"]:
                candidates[association["module"]].add(class_name)
        entry["original_modules"] = [
            {
                "module": module,
                "status": "candidate",
                "classes": sorted(candidate_classes),
            }
            for module, candidate_classes in sorted(candidates.items())
        ]

    factories: dict[str, dict] = {}
    for recipe in load_recipes(repo_root):
        address = f"0x{recipe.address:08x}"
        candidates: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"resources": set(), "classes": set(), "events": set()}
        )
        for case in recipe.cases:
            if case.resource is None:
                continue
            screen = f"{case.resource.resource_file}:{case.resource.view_id}"
            for association in screens[screen]["original_modules"]:
                candidate = candidates[association["module"]]
                candidate["resources"].add(screen)
                candidate["classes"].update(association["classes"])
                candidate["events"].add(f"0x{case.event:04x}")
        factories[address] = {
            "name": recipe.name,
            "original_modules": [
                {
                    "module": module,
                    "status": "candidate",
                    "resources": sorted(evidence["resources"]),
                    "classes": sorted(evidence["classes"]),
                    "events": sorted(evidence["events"]),
                }
                for module, evidence in sorted(candidates.items())
            ],
        }

    tags: dict[str, dict] = {}
    for tag, ids in sorted(tag_nodes.items()):
        instances = [node_by_id[node_id] for node_id in ids]
        candidate_counts = Counter(
            (node["class"], node["class_source"], node["type_code"]) for node in instances
        )
        candidates = []
        for (class_name, class_source, type_code), count in sorted(
            candidate_counts.items(), key=lambda item: (-item[1], item[0])
        ):
            candidate_nodes = [
                node
                for node in instances
                if (node["class"], node["class_source"], node["type_code"])
                == (class_name, class_source, type_code)
            ]
            candidates.append(
                {
                    "class": class_name,
                    "class_source": class_source,
                    "type_code": type_code,
                    "count": count,
                    "screens": sorted({node["screen"] for node in candidate_nodes}),
                }
            )
        tags[tag] = {
            "tag_value": int(instances[0]["tag_value"]) if instances else 0,
            "instance_count": len(ids),
            "screen_count": len({node["screen"] for node in instances}),
            "ambiguous": len({candidate["class"] for candidate in candidates}) > 1,
            "candidates": candidates,
            "nodes": ids,
        }

    return {
        "source": {
            "path": IR_PATH,
            "resource_set_sha256": ir_data.get("resource_set_sha256", ""),
        },
        "policy": (
            "Mac resource evidence is a semantic oracle only; it does not establish "
            "Windows ABI, addresses, calling conventions, vtable slots, or inheritance."
        ),
        "summary": {
            "screens": len(screens),
            "nodes": len(nodes),
            "classes": len(classes),
            "declared_classes": len(
                {node["class"] for node in nodes if node["class_source"] == "declared"}
            ),
            "tags": len(tags),
            "ambiguous_tags": sum(entry["ambiguous"] for entry in tags.values()),
            "source_modules": len(source_modules["modules"]),
            "functions_with_source_module_evidence": len(source_modules["functions"]),
            "classes_with_source_module_evidence": sum(
                bool(entry["original_modules"]) for entry in classes.values()
            ),
            "screens_with_source_module_candidates": sum(
                bool(entry["original_modules"]) for entry in screens.values()
            ),
            "factories_with_source_module_candidates": sum(
                bool(entry["original_modules"]) for entry in factories.values()
            ),
        },
        "screens": screens,
        "classes": classes,
        "tags": tags,
        "nodes": nodes,
        "factories": factories,
        "source_modules": {
            "policy": (
                "Function and qualified-class associations are confirmed by direct Windows "
                "source-path use. Mac screen and generated-factory joins are candidates only; "
                "they do not prove Windows ownership or ABI."
            ),
            "modules": source_modules["modules"],
            "functions": source_modules["functions"],
        },
    }


def tag_hints(index: dict, tags: Iterable[str], *, max_candidates: int = 4) -> list[str]:
    lines: list[str] = []
    tag_index = index.get("tags", {})
    for tag in sorted(set(tags)):
        entry = tag_index.get(tag)
        if entry is None:
            continue
        candidates = entry["candidates"][:max_candidates]
        rendered = []
        for candidate in candidates:
            source = "Mac class" if candidate["class_source"] == "declared" else "type family"
            rendered.append(f"{candidate['class']} ({candidate['count']}, {source})")
        ambiguity = " ambiguous" if entry["ambiguous"] else ""
        lines.append(
            f"  {tag!r}: {', '.join(rendered)} across "
            f"{entry['screen_count']} screen(s){ambiguity}"
        )
    return lines


def source_module_hints(index: dict, address: int, name: str) -> list[str]:
    """Render actionable original-module evidence for a portprep dossier."""
    rows: list[str] = []
    address_key = f"0x{address:08x}"
    direct = index.get("source_modules", {}).get("functions", {}).get(address_key)
    if direct:
        for association in direct["modules"]:
            rows.append(
                f"  {association['module']}: confirmed by direct source-path use in {address_key}"
            )

    owner = name.split("::", 1)[0] if "::" in name else ""
    class_entry = index.get("classes", {}).get(owner)
    if class_entry:
        for association in class_entry.get("original_modules", []):
            rows.append(
                f"  {association['module']}: confirmed class owner {owner}; "
                f"Mac instances in {', '.join(class_entry['screens'][:4])}"
            )

    factory = index.get("factories", {}).get(address_key)
    if factory:
        for association in factory.get("original_modules", []):
            rows.append(
                f"  {association['module']}: candidate via Mac classes "
                f"{', '.join(association['classes'][:4])} in "
                f"{', '.join(association['resources'][:3])}"
            )
    return list(dict.fromkeys(rows))
