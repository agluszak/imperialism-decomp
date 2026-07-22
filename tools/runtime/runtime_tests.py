#!/usr/bin/env python3
"""Run one compiled semantic test in the instrumented Imperialism executable."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build-runtime-tests"
sys.path.insert(0, str(REPO_ROOT))

from tools.workflow.ui_platform_diff import build_report


def retail_game_dir() -> Path:
    original = os.environ.get("ORIGINAL_BINARY")
    if not original:
        raise SystemExit("Set ORIGINAL_BINARY to a complete retail installation")
    game_dir = Path(original).resolve().parent
    if not (game_dir / "Data").is_dir():
        raise SystemExit(f"Missing {game_dir / 'Data'}")
    return game_dir


def windows_path(path: Path) -> str:
    result = subprocess.run(
        ["winepath", "-w", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


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


def apply_ui_oracle(result: dict) -> None:
    snapshots = result.get("ui_snapshots", [])
    if not snapshots:
        return
    report, errors = build_report(REPO_ROOT)
    if errors:
        raise ValueError("UI platform model is invalid: " + "; ".join(errors))
    comparisons = [compare_ui_snapshot(report, snapshot) for snapshot in snapshots]
    result["ui_oracle"] = {
        "status": (
            "passed"
            if all(comparison["status"] == "passed" for comparison in comparisons)
            else "failed"
        ),
        "snapshots": comparisons,
    }
    if result["ui_oracle"]["status"] == "failed":
        result["status"] = "failed"
        result["failure"] = "Mac-derived UI oracle mismatch"


def run_test(name: str, timeout: float) -> int:
    executable = BUILD_DIR / "Imperialism.exe"
    if not executable.is_file():
        raise SystemExit(f"Missing {executable}; run `just runtime-test-build` first")

    result_dir = BUILD_DIR / "runtime-results"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / f"{name}.json"
    result_path.unlink(missing_ok=True)

    environment = dict(os.environ)
    environment["IMPERIALISM_RUNTIME_TEST"] = name
    environment["IMPERIALISM_RUNTIME_TEST_RESULT"] = windows_path(result_path)
    environment["WINEDEBUG"] = environment.get("WINEDEBUG", "-all")

    try:
        completed = subprocess.run(
            ["wine", str(executable)],
            cwd=retail_game_dir(),
            env=environment,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"runtime test timed out after {timeout:g}s") from error

    if not result_path.is_file():
        raise SystemExit(
            f"runtime test exited with code {completed.returncode} without writing {result_path}"
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    try:
        apply_ui_oracle(result)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if completed.returncode != 0:
        print(f"Wine process exited with code {completed.returncode}", file=sys.stderr)
        return 1
    return 0 if result.get("status") == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", nargs="?", default="boot_managers")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    return run_test(args.name, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
