"""Semantic UI-tree oracle for instrumented runtime results."""

from __future__ import annotations

from pathlib import Path

from tools.workflow.ui_platform_diff import build_report

REPO_ROOT = Path(__file__).resolve().parents[3]

def semantic_node_paths(nodes: dict[str, dict]) -> dict[str, tuple[str, dict]]:
    paths: dict[str, str] = {}
    occurrences: dict[tuple[str | None, str], int] = {}
    result: dict[str, tuple[str, dict]] = {}
    for node_id, row in nodes.items():
        semantic = row["semantic"]
        parent_id = semantic["parent_id"]
        tag = semantic["tag"]
        occurrence_key = (parent_id, tag)
        occurrence = occurrences.get(occurrence_key, 0) + 1
        occurrences[occurrence_key] = occurrence
        tag_value = int.from_bytes(tag.encode("ascii"), "big")
        segment = f"{tag_value:08x}#{occurrence}"
        path = segment if parent_id is None else f"{paths[parent_id]}/{segment}"
        paths[node_id] = path
        result[path] = (node_id, row)
    return result


def expected_case_for_event(report: dict, event: int) -> tuple[str, dict]:
    event_key = f"0x{event:04x}"
    matches = [
        (function_key, function["cases"][event_key])
        for function_key, function in report["functions"].items()
        if event_key in function["cases"]
    ]
    if len(matches) != 1:
        raise ValueError(
            f"event {event_key} maps to {len(matches)} generated UI cases; expected one"
        )
    return matches[0]


def compare_ui_snapshot(report: dict, snapshot: dict) -> dict:
    event = int(snapshot["event"])
    event_key = f"0x{event:04x}"
    function_key, case = expected_case_for_event(report, event)
    expected = semantic_node_paths(case["nodes"])
    live = {str(node["path"]): node for node in snapshot.get("nodes", [])}
    differences: list[dict] = []

    for path in sorted(set(expected) - set(live)):
        node_id, row = expected[path]
        differences.append(
            {
                "kind": "missing_node",
                "path": path,
                "node_id": node_id,
                "tag": row["tag"],
                "source": row["mac_source"] or row["windows_binary_evidence"],
            }
        )
    for path in sorted(set(live) - set(expected)):
        node = live[path]
        differences.append(
            {
                "kind": "extra_node",
                "path": path,
                "tag": node["tag"],
                "class": node["class"],
            }
        )

    field_map = {
        "class_name": "class",
        "geometry": "bounds",
        "state": "state",
        "enabled": "enabled",
        "control_value": "control_value",
    }
    for path in sorted(set(expected) & set(live)):
        node_id, row = expected[path]
        semantic = row["semantic"]
        actual = live[path]
        checks = [
            (expected_name, live_name, semantic[expected_name])
            for expected_name, live_name in field_map.items()
        ]
        family = semantic["family"]
        if family.get("picture_id") is not None:
            checks.append(("picture_id", "picture_id", family["picture_id"]))
        text = family.get("text")
        if text is not None and text.get("value") is not None:
            checks.append(("text", "text", text["value"]))
        for expected_name, live_name, expected_value in checks:
            if isinstance(expected_value, tuple):
                expected_value = list(expected_value)
            actual_value = actual.get(live_name)
            if actual_value != expected_value:
                differences.append(
                    {
                        "kind": "field_mismatch",
                        "path": path,
                        "node_id": node_id,
                        "tag": row["tag"],
                        "field": expected_name,
                        "expected": expected_value,
                        "actual": actual_value,
                        "classification": row["classification"],
                        "source": row["mac_source"] or row["windows_binary_evidence"],
                    }
                )

    return {
        "event": event_key,
        "factory": function_key,
        "source": case["source"],
        "nodes_checked": len(expected),
        "status": "passed" if not differences else "failed",
        "differences": differences,
    }


def evaluate_ui_oracle(result: dict) -> dict | None:
    snapshots = result.get("ui_snapshots", [])
    if not snapshots:
        return None
    report, errors = build_report(REPO_ROOT)
    if errors:
        raise ValueError("UI platform model is invalid: " + "; ".join(errors))
    comparisons = [compare_ui_snapshot(report, snapshot) for snapshot in snapshots]
    return {
        "status": (
            "passed"
            if all(comparison["status"] == "passed" for comparison in comparisons)
            else "failed"
        ),
        "snapshots": comparisons,
    }


def apply_ui_oracle(result: dict) -> None:
    comparison = evaluate_ui_oracle(result)
    if comparison is None:
        return
    result["ui_oracle"] = comparison
    if result["ui_oracle"]["status"] == "failed":
        result["status"] = "failed"
        result["failure"] = "Mac-derived UI oracle mismatch"
