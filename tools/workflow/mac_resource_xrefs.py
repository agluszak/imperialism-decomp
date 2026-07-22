#!/usr/bin/env python3
"""Build and query a file-scoped Mac resource reference graph.

The graph joins committed resource metadata with generated Windows UI ownership
and statically visible ResolveControlByTag calls.  Mac evidence remains a
semantic oracle only; no edge establishes Windows ABI facts.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re

from tools.common.file_scan import iter_files
from tools.common.repo import repo_root_from_file
from tools.ui_codegen import IR_PATH, load_recipes, load_ui_views
from tools.workflow.mac_control_usage import build_index as build_control_index


FORMAT_VERSION = 1
GRAPH_PATH = "docs/reference/mac_resource_xrefs.json"
RESOURCE_DIR = "vendor/macos_codewarrior/evidence/resources"
PICTURES_PATH = f"{RESOURCE_DIR}/pictures.csv"
STRINGS_PATH = f"{RESOURCE_DIR}/strings.csv"
TEXT_STYLES_PATH = f"{RESOURCE_DIR}/text_styles.csv"
TEXT_RESOURCES_PATH = f"{RESOURCE_DIR}/text_resources.json"
MANIFEST_PATH = "config/ui_factory_codegen.yml"

_FUNCTION_RE = re.compile(r"^// FUNCTION: IMPERIALISM (0x[0-9a-fA-F]+)$", re.MULTILINE)
_RESOLVE_TAG_RE = re.compile(r"ResolveControlByTag\s*\(\s*(0x[0-9a-fA-F]+)[uUlL]*")

DANGLING_OWNERS = {
    "references_picture": (
        "The file-scoped PICT target is absent from committed metadata; do not resolve "
        "the colliding numeric ID from another resource file.",
        "imperialism-decomp-1uj.77.5",
    ),
    "references_string": (
        "The file-scoped STR# entry is absent from committed metadata; retain the "
        "reference until string-resource recovery explains its Resource Manager scope.",
        "imperialism-decomp-1uj.77.3",
    ),
    "references_text_style": (
        "The file-scoped TxSt target is absent; the decoded style ID is retained without "
        "guessing which other open resource file supplied the runtime fallback.",
        "imperialism-decomp-1uj.77.9",
    ),
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _view_id(resource_file: str, view_id: int) -> str:
    return f"{resource_file}:View:{view_id}"


def _view_node_id(resource_file: str, view_id: int, offset: int) -> str:
    return f"{_view_id(resource_file, view_id)}@0x{offset:04x}"


def _picture_id(resource_file: str, resource_id: int) -> str:
    return f"{resource_file}:PICT:{resource_id}"


def _string_id(resource_file: str, group_id: int, string_index: int) -> str:
    return f"{resource_file}:STR#:{group_id}:{string_index}"


def _text_style_id(resource_file: str, resource_id: int) -> str:
    return f"{resource_file}:TxSt:{resource_id}"


def _text_id(resource_file: str, resource_id: int) -> str:
    return f"{resource_file}:TEXT:{resource_id}"


def _style_scrap_id(resource_file: str, resource_id: int) -> str:
    return f"{resource_file}:styl:{resource_id}"


def _class_id(class_name: str) -> str:
    return f"mac_class:{class_name}"


def _tag_id(tag_value: int) -> str:
    return f"control_tag:0x{tag_value & 0xFFFFFFFF:08x}"


def _event_id(event: int) -> str:
    return f"windows_event:0x{event:04x}"


def _factory_id(address: int) -> str:
    return f"windows_factory:0x{address:08x}"


def _function_id(address: int) -> str:
    return f"windows_function:0x{address:08x}"


def _add_node(nodes: dict[str, dict], node_id: str, kind: str, **metadata: object) -> None:
    candidate = {"kind": kind, **metadata}
    existing = nodes.get(node_id)
    if existing is not None and existing != candidate:
        raise ValueError(f"conflicting graph node {node_id}")
    nodes[node_id] = candidate


def _add_edge(
    edges: list[dict],
    nodes: dict[str, dict],
    source: str,
    relation: str,
    target: str,
) -> None:
    edge = {"from": source, "relation": relation, "to": target}
    if target in nodes:
        edge["status"] = "resolved"
    else:
        explanation, bead = DANGLING_OWNERS[relation]
        edge.update(status="dangling_explained", explanation=explanation, bead=bead)
    edges.append(edge)


def _tag_text(value: int) -> str:
    try:
        return (value & 0xFFFFFFFF).to_bytes(4, "big").decode("mac_roman")
    except (OverflowError, UnicodeDecodeError):
        return ""


def _source_tag_edges(repo_root: Path, nodes: dict[str, dict], edges: list[dict]) -> None:
    known_tags = {
        int(node_id.rsplit("0x", 1)[1], 16)
        for node_id, node in nodes.items()
        if node["kind"] == "control_tag"
    }
    for path in iter_files([str(repo_root / "src" / "game")], patterns=("*.cpp",)):
        source = path.read_text(encoding="utf-8", errors="replace")
        markers = list(_FUNCTION_RE.finditer(source))
        for index, marker in enumerate(markers):
            body_end = markers[index + 1].start() if index + 1 < len(markers) else len(source)
            body = source[marker.end() : body_end]
            address = int(marker.group(1), 0)
            tag_values = sorted(
                {
                    int(match.group(1), 0) & 0xFFFFFFFF
                    for match in _RESOLVE_TAG_RE.finditer(body)
                    if (int(match.group(1), 0) & 0xFFFFFFFF) in known_tags
                }
            )
            if not tag_values:
                continue
            function = _function_id(address)
            _add_node(
                nodes,
                function,
                "windows_function",
                address=f"0x{address:08x}",
                source=str(path.relative_to(repo_root)),
            )
            for tag_value in tag_values:
                _add_edge(edges, nodes, function, "resolves_control_tag", _tag_id(tag_value))


def build_graph(repo_root: Path) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    for row in _read_csv(repo_root / PICTURES_PATH):
        node_id = _picture_id(row["resource_file"], int(row["resource_id"]))
        _add_node(
            nodes,
            node_id,
            "pict",
            resource_file=row["resource_file"],
            resource_id=int(row["resource_id"]),
            name=row["name"],
            width=int(row["width"]),
            height=int(row["height"]),
            sha256=row["sha256"],
        )
    for row in _read_csv(repo_root / STRINGS_PATH):
        node_id = _string_id(
            row["resource_file"], int(row["group_id"]), int(row["string_index"])
        )
        _add_node(
            nodes,
            node_id,
            "str_entry",
            resource_file=row["resource_file"],
            group_id=int(row["group_id"]),
            string_index=int(row["string_index"]),
            group_name=row["group_name"],
            text=row["text"],
        )
    for row in _read_csv(repo_root / TEXT_STYLES_PATH):
        node_id = _text_style_id(row["resource_file"], int(row["resource_id"]))
        _add_node(
            nodes,
            node_id,
            "txst",
            resource_file=row["resource_file"],
            resource_id=int(row["resource_id"]),
            name=row["name"],
            font_name=row["font_name"],
            point_size=int(row["point_size"]),
            face_flags=int(row["face_flags"]),
            face_flag_names=row["face_flag_names"].split(";") if row["face_flag_names"] else [],
            foreground_color=row["foreground_color"],
            decoder_confidence=row["decoder_confidence"],
            size=int(row["size"]),
            sha256=row["sha256"],
        )

    text_resources = json.loads((repo_root / TEXT_RESOURCES_PATH).read_text(encoding="utf-8"))
    for row in text_resources["texts"]:
        node_id = _text_id(str(row["resource_file"]), int(row["resource_id"]))
        _add_node(
            nodes,
            node_id,
            "text",
            resource_file=row["resource_file"],
            resource_id=int(row["resource_id"]),
            name=row["name"],
            size=int(row["size"]),
            sha256=row["sha256"],
            text=row["text"],
            decoder_confidence=row["decoder_confidence"],
        )
    for row in text_resources["style_scraps"]:
        node_id = _style_scrap_id(str(row["resource_file"]), int(row["resource_id"]))
        _add_node(
            nodes,
            node_id,
            "style_scrap",
            resource_file=row["resource_file"],
            resource_id=int(row["resource_id"]),
            name=row["name"],
            size=int(row["size"]),
            sha256=row["sha256"],
            run_count=int(row["run_count"]),
            runs=row["runs"],
            decoder_confidence=row["decoder_confidence"],
        )
        _add_edge(
            edges,
            nodes,
            _text_id(str(row["resource_file"]), int(row["resource_id"])),
            "has_style_scrap",
            node_id,
        )

    control_index = build_control_index(repo_root)
    control_nodes = {
        (str(node["screen"]), int(node["offset"])): node
        for node in control_index["nodes"]
    }
    for class_name, entry in control_index["classes"].items():
        _add_node(
            nodes,
            _class_id(class_name),
            "mac_class",
            name=class_name,
            instance_count=entry["instance_count"],
            windows_header=(repo_root / "include/game" / f"{class_name}.h").is_file(),
        )
    for tag, entry in control_index["tags"].items():
        tag_value = int(entry["tag_value"])
        _add_node(
            nodes,
            _tag_id(tag_value),
            "control_tag",
            tag=tag,
            tag_value=tag_value,
            instance_count=entry["instance_count"],
        )

    views = load_ui_views(repo_root)
    for key, view in sorted(views.items(), key=lambda item: item[0].text()):
        view_node = _view_id(key.resource_file, key.view_id)
        _add_node(
            nodes,
            view_node,
            "view",
            resource_file=key.resource_file,
            resource_id=key.view_id,
            name=str(view.get("view_name", "")),
            node_count=len(view.get("nodes", [])),
        )
        for node in sorted(view.get("nodes", []), key=lambda value: int(value["offset"])):
            offset = int(node["offset"])
            source = _view_node_id(key.resource_file, key.view_id, offset)
            control_node = control_nodes[(key.text(), offset)]
            _add_node(
                nodes,
                source,
                "view_node",
                view=view_node,
                offset=offset,
                tag=str(node.get("tag", "")),
                type_code=str(node.get("type_code", "")),
                class_name=str(control_node["class"]),
                class_source=str(control_node["class_source"]),
            )
            _add_edge(edges, nodes, view_node, "contains_view_node", source)
            parent_offset = node.get("parent_offset")
            if parent_offset is not None:
                _add_edge(
                    edges,
                    nodes,
                    _view_node_id(key.resource_file, key.view_id, int(parent_offset)),
                    "contains_child_node",
                    source,
                )
            tag_value = int(node.get("tag_value", 0))
            if _tag_id(tag_value) in nodes:
                _add_edge(edges, nodes, source, "has_control_tag", _tag_id(tag_value))
            _add_edge(
                edges,
                nodes,
                source,
                "instantiates_mac_class",
                _class_id(str(control_node["class"])),
            )

            family = node.get("family", {})
            picture = family.get("picture_id")
            if picture not in (None, 0xFFFF):
                _add_edge(
                    edges,
                    nodes,
                    source,
                    "references_picture",
                    _picture_id(key.resource_file, int(picture)),
                )
            text_id = family.get("text_resource_id")
            text_index = family.get("text_resource_index")
            if text_id not in (None, 0xFFFF) and text_index not in (None, 0xFFFF):
                _add_edge(
                    edges,
                    nodes,
                    source,
                    "references_string",
                    _string_id(key.resource_file, int(text_id), int(text_index)),
                )
            style_id = family.get("text_style_id")
            if style_id not in (None, 0xFFFF):
                _add_edge(
                    edges,
                    nodes,
                    source,
                    "references_text_style",
                    _text_style_id(key.resource_file, int(style_id)),
                )

    for recipe in load_recipes(repo_root):
        factory = _factory_id(recipe.address)
        _add_node(
            nodes,
            factory,
            "windows_factory",
            address=f"0x{recipe.address:08x}",
            name=recipe.name,
        )
        for case in recipe.cases:
            event = _event_id(case.event)
            _add_node(nodes, event, "windows_event", event=f"0x{case.event:04x}")
            _add_edge(edges, nodes, factory, "handles_event", event)
            if case.resource is not None:
                _add_edge(
                    edges,
                    nodes,
                    event,
                    "builds_view",
                    _view_id(case.resource.resource_file, case.resource.view_id),
                )

    _source_tag_edges(repo_root, nodes, edges)
    edges.sort(key=lambda edge: (edge["from"], edge["relation"], edge["to"]))
    kind_counts: dict[str, int] = {}
    for node in nodes.values():
        kind = str(node["kind"])
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    relation_counts: dict[str, int] = {}
    for edge in edges:
        relation = str(edge["relation"])
        relation_counts[relation] = relation_counts.get(relation, 0) + 1
    dangling = [edge for edge in edges if edge["status"] != "resolved"]
    referenced_targets = {edge["to"] for edge in edges}
    unreferenced_resources = {
        kind: sorted(
            node_id
            for node_id, node in nodes.items()
            if node["kind"] == kind and node_id not in referenced_targets
        )
        for kind in ("pict", "str_entry", "txst", "text", "style_scrap")
    }
    dangling_by_relation: dict[str, int] = {}
    for edge in dangling:
        relation = str(edge["relation"])
        dangling_by_relation[relation] = dangling_by_relation.get(relation, 0) + 1
    missing_windows_classes = sorted(
        node["name"]
        for node in nodes.values()
        if node["kind"] == "mac_class" and not node["windows_header"]
    )
    return {
        "format_version": FORMAT_VERSION,
        "policy": (
            "Resource identities are file scoped. Mac evidence is semantic only and does "
            "not establish Windows addresses, ABI, vtables, calling conventions, or inheritance."
        ),
        "sources": {
            "views": IR_PATH,
            "pictures": PICTURES_PATH,
            "strings": STRINGS_PATH,
            "text_styles": TEXT_STYLES_PATH,
            "text_resources": TEXT_RESOURCES_PATH,
            "control_usage": "docs/reference/mac_control_usage.json",
            "windows_ui_ownership": MANIFEST_PATH,
            "text_and_styl": {"status": "decoded"},
        },
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "node_kinds": dict(sorted(kind_counts.items())),
            "edge_relations": dict(sorted(relation_counts.items())),
            "dangling_explained": len(dangling),
            "dangling_unexplained": sum(
                "explanation" not in edge or "bead" not in edge for edge in dangling
            ),
            "dangling_by_relation": dict(sorted(dangling_by_relation.items())),
            "unreferenced_resources": {
                kind: len(values) for kind, values in unreferenced_resources.items()
            },
            "mac_classes_without_windows_header": len(missing_windows_classes),
        },
        "mac_classes_without_windows_header": missing_windows_classes,
        "unreferenced_resources": unreferenced_resources,
        "nodes": dict(sorted(nodes.items())),
        "edges": edges,
    }


def render_graph(graph: dict) -> str:
    return json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def query_result(graph: dict, resource: str) -> dict:
    if resource not in graph["nodes"]:
        raise KeyError(resource)
    incoming = [edge for edge in graph["edges"] if edge["to"] == resource]
    outgoing = [edge for edge in graph["edges"] if edge["from"] == resource]
    edges_by_source: dict[str, list[dict]] = {}
    for edge in graph["edges"]:
        edges_by_source.setdefault(edge["from"], []).append(edge)
    pending = [resource]
    visited = {resource}
    dependency_edges: list[dict] = []
    while pending:
        source = pending.pop(0)
        for edge in edges_by_source.get(source, []):
            dependency_edges.append(edge)
            target = edge["to"]
            if target in graph["nodes"] and target not in visited:
                visited.add(target)
                pending.append(target)
    dependencies = {
        node_id: graph["nodes"][node_id]
        for node_id in sorted(visited - {resource})
    }
    return {
        "id": resource,
        "node": graph["nodes"][resource],
        "incoming": incoming,
        "outgoing": outgoing,
        "dependencies": dependencies,
        "dependency_edges": sorted(
            dependency_edges, key=lambda edge: (edge["from"], edge["relation"], edge["to"])
        ),
    }


def _query(graph: dict, resource: str, *, as_json: bool) -> None:
    try:
        result = query_result(graph, resource)
    except KeyError as exc:
        raise SystemExit(f"No resource-graph node for {resource!r}") from exc
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return
    node = result["node"]
    print(f"{resource} [{node['kind']}]")
    for key, value in node.items():
        if key != "kind":
            print(f"  {key}: {value}")
    incoming = result["incoming"]
    outgoing = result["outgoing"]
    print(f"  incoming ({len(incoming)}):")
    for edge in incoming:
        print(f"    {edge['relation']} <- {edge['from']} [{edge['status']}]")
    print(f"  outgoing ({len(outgoing)}):")
    for edge in outgoing:
        suffix = "" if edge["status"] == "resolved" else f" ({edge['bead']})"
        print(f"    {edge['relation']} -> {edge['to']} [{edge['status']}]{suffix}")
    dependencies_by_kind: dict[str, list[str]] = {}
    for node_id, dependency in result["dependencies"].items():
        dependencies_by_kind.setdefault(dependency["kind"], []).append(node_id)
    print(f"  transitive dependency set ({len(result['dependencies'])}):")
    for kind in sorted(dependencies_by_kind):
        values = dependencies_by_kind[kind]
        print(f"    {kind} ({len(values)}):")
        for node_id in values:
            print(f"      {node_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resource", nargs="?")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if sum((args.write, args.check, args.resource is not None)) != 1:
        parser.error("choose exactly one of RESOURCE, --write, or --check")
    repo_root = repo_root_from_file(__file__)
    graph = build_graph(repo_root)
    rendered = render_graph(graph)
    path = repo_root / GRAPH_PATH
    if args.write:
        path.write_text(rendered, encoding="utf-8")
        print(f"Wrote {GRAPH_PATH}: {graph['summary']['nodes']} nodes, {graph['summary']['edges']} edges")
        return 0
    if args.check:
        current = path.read_text(encoding="utf-8") if path.is_file() else ""
        if current != rendered:
            raise SystemExit(f"{GRAPH_PATH} is stale; run just mac-resource-xrefs-update")
        if graph["summary"]["dangling_unexplained"]:
            raise SystemExit("Mac resource graph contains unexplained dangling edges")
        print(
            "Mac resource xrefs passed: "
            f"nodes={graph['summary']['nodes']}, edges={graph['summary']['edges']}, "
            f"dangling_explained={graph['summary']['dangling_explained']}"
        )
        return 0
    _query(graph, args.resource, as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
