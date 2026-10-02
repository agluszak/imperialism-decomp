"""Summarize saved authored-function evidence and compare report datasets."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

from reccmp.compare.call_census import call_delta

from tools.common.reccmp_report import function_counts, read_summary
from tools.common.repo import repo_root_from_file


def report_delta(head: dict, base: dict) -> dict:
    if head["target"] != base["target"]:
        raise ValueError("Reports target different images")
    if head["inputs"]["orig"]["sha256"] != base["inputs"]["orig"]["sha256"]:
        raise ValueError("Reports use different retail binaries")
    old = {int(row["orig"], 16): row for row in base["functions"]}
    new = {int(row["orig"], 16): row for row in head["functions"]}
    transitions = Counter(
        (old[address]["outcome"], new[address]["outcome"])
        for address in old.keys() & new.keys()
    )
    return {
        "shared_functions": len(old.keys() & new.keys()),
        "added_to_dataset": [
            hex(address) for address in sorted(new.keys() - old.keys())
        ],
        "removed_from_dataset": [
            hex(address) for address in sorted(old.keys() - new.keys())
        ],
        "outcome_transitions": [
            {"base": before, "head": after, "count": count}
            for (before, after), count in sorted(transitions.items())
        ],
    }


def call_queue(census: dict) -> list[dict]:
    rows = []
    for function in census["functions"]:
        original, rebuilt = function["orig"], function["recomp"]
        if original["calls"] is None or rebuilt["calls"] is None:
            rows.append({"orig": function["address"], "category": "incomplete-body"})
            continue
        delta = call_delta(original["calls"], rebuilt["calls"])
        if delta["category"] != "identical-canonical-sequence":
            rows.append({"orig": function["address"], **delta})
    return rows


def reference_groups(summary: dict, census: dict) -> dict:
    non_clean = {
        row["orig"]: row
        for row in summary["functions"]
        if row["outcome"] != "no-differences"
    }

    def rows(groups: dict[str, dict]) -> list[dict]:
        return sorted(
            (
                {
                    **group["identity"],
                    "functions": sorted(
                        group["functions"],
                        key=lambda item: int(item["orig"], 16),
                    ),
                }
                for group in groups.values()
                if len(group["functions"]) > 1
            ),
            key=lambda group: (-len(group["functions"]), str(group)),
        )

    data_groups: dict[str, dict] = {}
    source_groups: dict[str, dict] = {}
    for address, function in non_clean.items():
        reference = {key: function[key] for key in ("orig", "name", "outcome")}
        source = function.get("source")
        if source and source.get("path"):
            path = source["path"]
            source_groups.setdefault(
                path,
                {"identity": {"path": path}, "functions": []},
            )["functions"].append(reference)
        seen_objects: set[str] = set()
        for difference in function.get("data", []):
            obj = difference.get("object")
            if obj is None:
                continue
            original = obj.get("orig")
            if not original or original in seen_objects:
                continue
            seen_objects.add(original)
            data_groups.setdefault(
                original,
                {
                    "identity": {
                        "orig": original,
                        "name": obj.get("name", ""),
                    },
                    "functions": [],
                },
            )["functions"].append(reference)

    call_groups: dict[str, dict] = {}
    for function in census["functions"]:
        reference = non_clean.get(function["address"])
        calls = function["orig"]["calls"]
        if reference is None or calls is None:
            continue
        seen_targets: set[str] = set()
        for call in calls:
            target = call["identity"]
            if target in seen_targets:
                continue
            seen_targets.add(target)
            call_groups.setdefault(
                target,
                {
                    "identity": {
                        "identity": target,
                        "name": call.get("name", ""),
                    },
                    "functions": [],
                },
            )["functions"].append(
                {key: reference[key] for key in ("orig", "name", "outcome")}
            )

    return {
        "data_references": {
            "measure": (
                "non-clean authored reports that contain a difference record for "
                "the same original object"
            ),
            "groups": rows(data_groups),
        },
        "direct_call_targets": {
            "measure": (
                "non-clean authored functions that directly call the same original "
                "target in the saved census"
            ),
            "groups": rows(call_groups),
        },
        "source_owners": {
            "measure": (
                "non-clean authored functions whose markers are in the same source file"
            ),
            "groups": rows(source_groups),
        },
    }


def saved_report(directory: Path) -> dict:
    summary = read_summary(directory)
    checks = json.loads((directory / "checks.json").read_text())
    return {
        "target": summary["target"],
        **function_counts(summary["functions"]),
        "datacmp": {
            key: value for key, value in checks["datacmp"].items() if key != "variables"
        },
        "vtables": checks["vtables"]["counts"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--base", type=Path, help="saved report from the merge-base build"
    )
    parser.add_argument("--base-ref", default="origin/main")
    parser.add_argument("--output", type=Path, help="write JSON instead of printing it")
    parser.add_argument(
        "--queue", action="store_true", help="include direct-call asymmetry queue"
    )
    parser.add_argument(
        "--campaigns",
        action="store_true",
        help="group non-clean saved evidence by shared references and source owners",
    )
    args = parser.parse_args()
    result: dict[str, object] = {"head": saved_report(args.report)}
    if args.base:
        repo = repo_root_from_file(__file__)
        expected = subprocess.check_output(
            ["git", "merge-base", "HEAD", args.base_ref],
            cwd=repo,
            text=True,
        ).strip()
        selection = json.loads((args.base / "selection.json").read_text())
        if selection["revision"] != expected or selection["scope"] != "all-authored":
            parser.error(
                "Base report must cover all authored functions at the merge base"
            )
        result["base"] = saved_report(args.base)
        result["delta"] = report_delta(
            read_summary(args.report), read_summary(args.base)
        )
    if args.queue or args.campaigns:
        census = json.loads((args.report / "direct-calls.json").read_text())
        if args.queue:
            result["call_asymmetries"] = call_queue(census)
        if args.campaigns:
            result["campaigns"] = reference_groups(read_summary(args.report), census)
    encoded = json.dumps(result, indent=1) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
        print(f"Saved report: {args.output}")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
