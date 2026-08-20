#!/usr/bin/env python3
"""Build declared Mac-resource versus generated Windows UI semantic deltas."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path

import yaml

from tools.ui_codegen import (
    CLASS_ALIASES,
    DEFAULT_CLASSES,
    _render_factory_with_map,
    apply_case_windows_overrides,
    load_city_building_action_visuals,
    load_city_building_visuals,
    load_city_dialog_controls,
    load_diplomacy_map_key_names,
    load_recipes,
    load_text_resources,
    load_ui_views,
    load_windows_views,
    normalize_resource_view,
)


DELTA_CONFIG_PATH = "config/ui_platform_deltas.yml"


def _load_delta_config(repo_root: Path) -> dict:
    data = yaml.safe_load((repo_root / DELTA_CONFIG_PATH).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{DELTA_CONFIG_PATH}: expected a mapping")
    allowed = {
        "class_substitutions",
        "functional_parity_cases",
        "node_property_patches",
        "diplomacy_map_key_names",
        "transport_picture_children",
        "city_buildings",
        "city_building_actions",
        "city_dialog_controls",
    }
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"{DELTA_CONFIG_PATH}: unknown fields {', '.join(unknown)}")
    substitutions = data.get("class_substitutions", {})
    if not isinstance(substitutions, dict):
        raise ValueError(f"{DELTA_CONFIG_PATH}: class_substitutions must be a mapping")
    for mac_class, row in substitutions.items():
        if not isinstance(row, dict) or set(row) != {"windows_class", "reason", "evidence"}:
            raise ValueError(f"{DELTA_CONFIG_PATH}: malformed class substitution {mac_class}")
        if not all(str(row[key]).strip() for key in row):
            raise ValueError(f"{DELTA_CONFIG_PATH}: empty class substitution evidence {mac_class}")
    parity = data.get("functional_parity_cases", {})
    if not isinstance(parity, dict):
        raise ValueError(f"{DELTA_CONFIG_PATH}: functional_parity_cases must be a mapping")
    for key, row in parity.items():
        if not isinstance(row, dict) or set(row) != {"evidence"} or not str(row["evidence"]).strip():
            raise ValueError(f"{DELTA_CONFIG_PATH}: malformed functional parity case {key}")
    return data


def _class_from_raw_node(node: dict) -> str:
    declared = str(node.get("class_name", ""))
    return declared or DEFAULT_CLASSES[str(node["type_code"])]


def _semantic_snapshot(node) -> dict:
    data = asdict(node)
    data.pop("source", None)
    data.pop("confidence", None)
    return data


def build_report(repo_root: Path) -> tuple[dict, list[str]]:
    config = _load_delta_config(repo_root)
    diplomacy_map_key_names = load_diplomacy_map_key_names(repo_root)
    load_city_building_visuals(repo_root)
    load_city_building_action_visuals(repo_root)
    load_city_dialog_controls(repo_root)
    recipes = load_recipes(repo_root)
    raw_views = load_ui_views(repo_root)
    text_resources = load_text_resources(repo_root)
    windows_views = load_windows_views(repo_root)
    declared_substitutions = config["class_substitutions"]
    declared_parity = config["functional_parity_cases"]
    errors: list[str] = []

    configured_aliases = {
        mac_class: str(row["windows_class"])
        for mac_class, row in declared_substitutions.items()
    }
    if configured_aliases != CLASS_ALIASES:
        errors.append(
            f"{DELTA_CONFIG_PATH}: class substitutions {configured_aliases!r} "
            f"do not exactly match generator aliases {CLASS_ALIASES!r}"
        )

    observed_parity: set[str] = set()
    observed_substitutions: set[str] = set()
    functions: dict[str, dict] = {}
    summary = {
        "functions": len(recipes),
        "cases": 0,
        "mapped_mac_cases": 0,
        "functional_parity_cases": 0,
        "windows_only_cases": 0,
        "nodes": 0,
        "same_semantics": 0,
        "expected_windows_field_override": 0,
        "expected_windows_class_substitution": 0,
        "windows_only_nodes": 0,
        "diplomacy_map_key_names": len(diplomacy_map_key_names.children),
        "unexplained_deltas": 0,
    }

    for recipe in recipes:
        generated_cpp, source_map = _render_factory_with_map(
            recipe, raw_views, text_resources, windows_views
        )
        function_key = f"0x{recipe.address:08x}"
        function_row = {
            "name": recipe.name,
            "generated_file": recipe.output_name,
            "generated_sha256": hashlib.sha256(generated_cpp.encode("utf-8")).hexdigest(),
            "cases": {},
        }
        for case in recipe.cases:
            summary["cases"] += 1
            event_key = f"0x{case.event:04x}"
            parity_key = f"{function_key}/{event_key}"
            generated_case = source_map["cases"].get(event_key, {})
            if case.resource is not None:
                raw_view = raw_views[case.resource]
                mac_semantic_view = normalize_resource_view(
                    case.resource, raw_view, text_resources
                )
                semantic_view = apply_case_windows_overrides(
                    recipe, case, mac_semantic_view
                )
                case_classification = "mapped_mac_resource"
                summary["mapped_mac_cases"] += 1
                if case.evidence:
                    case_classification = "functional_parity_extension"
                    summary["functional_parity_cases"] += 1
                    observed_parity.add(parity_key)
                    declared = declared_parity.get(parity_key)
                    if declared is None:
                        errors.append(f"{parity_key}: undeclared functional-parity extension")
                    elif str(declared["evidence"]) not in case.evidence:
                        errors.append(f"{parity_key}: declared parity evidence does not match manifest")
                raw_by_id = {
                    f"0x{int(node['offset']):04x}": node for node in raw_view.get("nodes", [])
                }
                if len(raw_by_id) != len(mac_semantic_view.nodes):
                    errors.append(
                        f"{parity_key}: Mac node count {len(raw_by_id)} != normalized node count "
                        f"{len(mac_semantic_view.nodes)}"
                    )
                mac_nodes_by_id = {node.node_id: node for node in mac_semantic_view.nodes}
                overrides_by_id = {
                    override.node_id: override for override in case.windows_overrides
                }
                node_rows: dict[str, dict] = {}
                for node in semantic_view.nodes:
                    raw = raw_by_id.get(node.node_id)
                    if raw is None:
                        errors.append(f"{parity_key}/{node.node_id}: normalized node has no Mac record")
                        continue
                    raw_class = _class_from_raw_node(raw)
                    classification = "same_semantics"
                    delta: dict | None = None
                    windows_binary_evidence = (
                        "not encoded; Mac semantic resource is canonical for functional parity"
                    )
                    override = overrides_by_id.get(node.node_id)
                    if override is not None:
                        mac_node = mac_nodes_by_id[node.node_id]
                        classification = "expected_windows_field_override"
                        windows_binary_evidence = override.evidence
                        delta = {
                            "field": "enabled",
                            "mac": mac_node.enabled,
                            "windows": node.enabled,
                            "reason": "original Windows builder differs from the Mac resource",
                            "evidence": override.evidence,
                        }
                    if raw_class != node.class_name:
                        declaration = declared_substitutions.get(raw_class)
                        if declaration is None or declaration["windows_class"] != node.class_name:
                            classification = "unexplained_delta"
                            summary["unexplained_deltas"] += 1
                            errors.append(
                                f"{parity_key}/{node.node_id}: unexplained class delta "
                                f"{raw_class} -> {node.class_name}"
                            )
                        else:
                            classification = "expected_windows_class_substitution"
                            observed_substitutions.add(raw_class)
                            delta = {
                                "field": "class",
                                "mac": raw_class,
                                "windows": node.class_name,
                                "reason": declaration["reason"],
                                "evidence": declaration["evidence"],
                            }
                    generated_node = generated_case.get("nodes", {}).get(node.node_id)
                    if generated_node is None:
                        errors.append(f"{parity_key}/{node.node_id}: absent from generated source map")
                        generated_lines = None
                    else:
                        generated_lines = generated_node["generated_lines"]
                        if generated_node["class"] != node.class_name or generated_node["tag"] != node.tag:
                            errors.append(f"{parity_key}/{node.node_id}: generated source-map identity drift")
                    summary["nodes"] += 1
                    if classification != "unexplained_delta":
                        summary[classification] += 1
                    node_rows[node.node_id] = {
                        "tag": node.tag,
                        "classification": classification,
                        "mac_source": f"{case.resource.text()} node {node.node_id}",
                        "windows_binary_evidence": windows_binary_evidence,
                        "generated_lines": generated_lines,
                        "semantic": _semantic_snapshot(node),
                        "delta": delta,
                    }
                source = case.resource.text()
            elif case.windows_view is not None:
                semantic_view = windows_views[case.windows_view]
                case_classification = "windows_only"
                summary["windows_only_cases"] += 1
                node_rows = {}
                for node in semantic_view.nodes:
                    generated_node = generated_case.get("nodes", {}).get(node.node_id)
                    if generated_node is None:
                        errors.append(f"{parity_key}/{node.node_id}: absent from generated source map")
                        generated_lines = None
                    else:
                        generated_lines = generated_node["generated_lines"]
                    summary["nodes"] += 1
                    summary["windows_only_nodes"] += 1
                    node_rows[node.node_id] = {
                        "tag": node.tag,
                        "classification": "windows_only_node",
                        "mac_source": None,
                        "windows_binary_evidence": node.source,
                        "generated_lines": generated_lines,
                        "semantic": _semantic_snapshot(node),
                        "delta": None,
                    }
                source = semantic_view.source
            else:
                case_classification = "rejected"
                node_rows = {}
                source = case.evidence
            function_row["cases"][event_key] = {
                "classification": case_classification,
                "source": source,
                "manifest_evidence": case.evidence,
                "nodes": node_rows,
            }
        functions[function_key] = function_row

    missing_parity = sorted(set(declared_parity) - observed_parity)
    if missing_parity:
        errors.append(f"{DELTA_CONFIG_PATH}: unobserved functional parity cases {', '.join(missing_parity)}")
    used_aliases = {
        _class_from_raw_node(node)
        for view in raw_views.values()
        for node in view.get("nodes", [])
    }
    missing_alias_evidence = sorted(
        alias for alias in CLASS_ALIASES if alias in used_aliases and alias not in observed_substitutions
    )
    # Aliases used only by currently unmapped Mac resources remain declared but
    # cannot appear as generated-node deltas yet.
    if missing_alias_evidence:
        mapped_resource_keys = {
            case.resource for recipe in recipes for case in recipe.cases if case.resource is not None
        }
        mapped_classes = {
            _class_from_raw_node(node)
            for key in mapped_resource_keys
            for node in raw_views[key].get("nodes", [])
        }
        for alias in missing_alias_evidence:
            if alias in mapped_classes:
                errors.append(f"{DELTA_CONFIG_PATH}: mapped alias {alias} was not reported")

    report = {
        "policy": (
            "Mac resources own functional UI semantics for mapped cases. Windows binary evidence "
            "is required only for declared platform deltas and Windows-only trees; this report "
            "does not treat intentional deltas as source defects."
        ),
        "sources": {
            "manifest": "config/ui_factory_codegen.yml",
            "mac_views": "vendor/macos_codewarrior/evidence/resources/ui_views.json",
            "windows_only_views": "config/ui_factory_windows_views.yml",
            "declared_deltas": DELTA_CONFIG_PATH,
        },
        "summary": summary,
        "diplomacy_map_key_names": {
            "view": diplomacy_map_key_names.view.text(),
            "parent": {
                "node": f"0x{diplomacy_map_key_names.parent_id:04x}",
                "tag": diplomacy_map_key_names.parent_tag,
            },
            "evidence": diplomacy_map_key_names.evidence,
            "text": diplomacy_map_key_names.text,
            "children": [
                {
                    "node": f"0x{child.node_id:08x}",
                    "tag": child.tag,
                    "rect": child.rect,
                }
                for child in diplomacy_map_key_names.children
            ],
        },
        "functions": functions,
    }
    return report, errors
