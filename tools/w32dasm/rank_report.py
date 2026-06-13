#!/usr/bin/env python3
"""Build ranked work queues from read-only W32Dasm/Ghidra comparison reports."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from tools.w32dasm.parse_alf import DEFAULT_OUT_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_OUT_DIR, help="W32Dasm report directory")
    parser.add_argument("--top", type=int, default=250, help="Maximum ranked rows per output")
    return parser.parse_args()


def load_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_rows(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def instruction_map(report_dir: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in load_rows(report_dir / "instructions.csv"):
        result[row["address"]] = row["text"]
    return result


def rank_missing_xref_targets(
    missing_xrefs: list[dict[str, str]],
    instructions: dict[str, str],
    limit: int,
) -> list[dict[str, object]]:
    by_target: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in missing_xrefs:
        by_target[row["target_address"]].append(row)

    ranked: list[dict[str, object]] = []
    for target, rows in by_target.items():
        kinds = Counter(row["kind"] for row in rows)
        refs = [row["ref_address"] for row in rows[:12]]
        ranked.append(
            {
                "target_address": target,
                "missing_refs": len(rows),
                "call_refs": kinds.get("call", 0),
                "jump_refs": kinds.get("jump", 0),
                "sample_ref_addresses": " ".join(refs),
                "target_text": instructions.get(target, ""),
            }
        )
    ranked.sort(
        key=lambda row: (
            -int(row["missing_refs"]),
            -int(row["call_refs"]),
            str(row["target_address"]),
        )
    )
    for index, row in enumerate(ranked[:limit], start=1):
        row["rank"] = index
    return ranked[:limit]


def rank_missing_xref_sources(missing_xrefs: list[dict[str, str]], limit: int) -> list[dict[str, object]]:
    by_source: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in missing_xrefs:
        by_source[row["ref_address"]].append(row)

    ranked: list[dict[str, object]] = []
    for source, rows in by_source.items():
        kinds = Counter(row["kind"] for row in rows)
        targets = [row["target_address"] for row in rows[:12]]
        ranked.append(
            {
                "ref_address": source,
                "missing_targets": len(rows),
                "call_refs": kinds.get("call", 0),
                "jump_refs": kinds.get("jump", 0),
                "sample_target_addresses": " ".join(targets),
            }
        )
    ranked.sort(
        key=lambda row: (
            -int(row["missing_targets"]),
            -int(row["call_refs"]),
            str(row["ref_address"]),
        )
    )
    for index, row in enumerate(ranked[:limit], start=1):
        row["rank"] = index
    return ranked[:limit]


def rank_instruction_clusters(clusters: list[dict[str, str]], limit: int) -> list[dict[str, object]]:
    ranked = [
        {
            "start_address": row["start_address"],
            "end_address": row["end_address"],
            "issue": row["issue"],
            "instruction_count": int(row["instruction_count"]),
            "first_text": row["first_text"],
            "last_text": row["last_text"],
        }
        for row in clusters
    ]
    ranked.sort(
        key=lambda row: (
            -int(row["instruction_count"]),
            str(row["start_address"]),
        )
    )
    for index, row in enumerate(ranked[:limit], start=1):
        row["rank"] = index
    return ranked[:limit]


def classify_cluster(row: dict[str, object]) -> str:
    count = int(row["instruction_count"])
    first = str(row["first_text"]).lower()
    last = str(row["last_text"]).lower()
    if count > 32 and first in {"int 03", "nop"} and last == "int 03":
        return "padding_fill"
    if count > 32 and first == "int 03" and last.startswith("int "):
        return "padding_fill"
    if first.startswith("dword ") or first.startswith("byte "):
        return "probable_data"
    return "inspect"


def rank_actionable_instruction_clusters(
    clusters: list[dict[str, str]],
    limit: int,
) -> list[dict[str, object]]:
    ranked = rank_instruction_clusters(clusters, len(clusters))
    actionable: list[dict[str, object]] = []
    for row in ranked:
        classification = classify_cluster(row)
        row["classification"] = classification
        if classification == "padding_fill":
            continue
        actionable.append(row)
    actionable.sort(
        key=lambda row: (
            str(row["classification"]) != "inspect",
            -int(row["instruction_count"]),
            str(row["start_address"]),
        )
    )
    for index, row in enumerate(actionable[:limit], start=1):
        row["rank"] = index
    return actionable[:limit]


def rank_hints(hints: list[dict[str, str]], limit: int) -> list[dict[str, object]]:
    by_kind: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in hints:
        by_kind[row["kind"]].append(row)

    ranked: list[dict[str, object]] = []
    for kind, rows in by_kind.items():
        ranked.append(
            {
                "kind": kind,
                "count": len(rows),
                "sample_addresses": " ".join(row["address"] for row in rows[:12]),
                "sample_text": rows[0]["text"] if rows else "",
            }
        )
    ranked.sort(key=lambda row: (-int(row["count"]), str(row["kind"])))
    for index, row in enumerate(ranked[:limit], start=1):
        row["rank"] = index
    return ranked[:limit]


def extract_source_path(text: str) -> str:
    marker = '->"'
    if marker not in text:
        return ""
    suffix = text.split(marker, 1)[1]
    return suffix.split('"', 1)[0]


def rank_source_path_hints(hints: list[dict[str, str]], limit: int) -> list[dict[str, object]]:
    by_path: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in hints:
        path = extract_source_path(row["text"])
        if path.lower().endswith((".cpp", ".h", ".hpp", ".c")):
            by_path[path].append(row)

    ranked: list[dict[str, object]] = []
    for path, rows in by_path.items():
        ranked.append(
            {
                "source_path": path,
                "hint_count": len(rows),
                "sample_addresses": " ".join(row["address"] for row in rows[:20]),
            }
        )
    ranked.sort(key=lambda row: (-int(row["hint_count"]), str(row["source_path"])))
    for index, row in enumerate(ranked[:limit], start=1):
        row["rank"] = index
    return ranked[:limit]


def write_source_path_summary(report_dir: Path, limit: int) -> list[dict[str, object]]:
    source_paths = load_rows(report_dir / "wpj_source_paths.csv")
    ranked = [{"rank": index, "path": row["path"]} for index, row in enumerate(source_paths[:limit], start=1)]
    write_rows(report_dir / "wpj_source_paths_ranked.csv", ["rank", "path"], ranked)
    return ranked


def main() -> int:
    args = parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=True)

    instructions = instruction_map(args.report_dir)
    missing_xrefs = load_rows(args.report_dir / "xrefs_missing_in_ghidra.csv")
    clusters = load_rows(args.report_dir / "instruction_gap_clusters.csv")
    hints = load_rows(args.report_dir / "hints.csv")

    xref_targets = rank_missing_xref_targets(missing_xrefs, instructions, args.top)
    xref_sources = rank_missing_xref_sources(missing_xrefs, args.top)
    instruction_clusters = rank_instruction_clusters(clusters, args.top)
    actionable_instruction_clusters = rank_actionable_instruction_clusters(clusters, args.top)
    hint_kinds = rank_hints(hints, args.top)
    source_path_hints = rank_source_path_hints(hints, args.top)
    source_paths = write_source_path_summary(args.report_dir, args.top)

    outputs = {
        "missing_xref_targets": str(args.report_dir / "missing_xref_targets_ranked.csv"),
        "missing_xref_sources": str(args.report_dir / "missing_xref_sources_ranked.csv"),
        "instruction_gap_clusters": str(args.report_dir / "instruction_gap_clusters_ranked.csv"),
        "instruction_gap_clusters_actionable": str(
            args.report_dir / "instruction_gap_clusters_actionable.csv"
        ),
        "hint_kinds": str(args.report_dir / "hint_kinds_ranked.csv"),
        "source_path_hints": str(args.report_dir / "source_path_hints_ranked.csv"),
        "wpj_source_paths": str(args.report_dir / "wpj_source_paths_ranked.csv"),
    }
    write_rows(
        args.report_dir / "missing_xref_targets_ranked.csv",
        [
            "rank",
            "target_address",
            "missing_refs",
            "call_refs",
            "jump_refs",
            "sample_ref_addresses",
            "target_text",
        ],
        xref_targets,
    )
    write_rows(
        args.report_dir / "missing_xref_sources_ranked.csv",
        ["rank", "ref_address", "missing_targets", "call_refs", "jump_refs", "sample_target_addresses"],
        xref_sources,
    )
    write_rows(
        args.report_dir / "instruction_gap_clusters_ranked.csv",
        ["rank", "start_address", "end_address", "issue", "instruction_count", "first_text", "last_text"],
        instruction_clusters,
    )
    write_rows(
        args.report_dir / "instruction_gap_clusters_actionable.csv",
        [
            "rank",
            "start_address",
            "end_address",
            "issue",
            "classification",
            "instruction_count",
            "first_text",
            "last_text",
        ],
        actionable_instruction_clusters,
    )
    write_rows(
        args.report_dir / "hint_kinds_ranked.csv",
        ["rank", "kind", "count", "sample_addresses", "sample_text"],
        hint_kinds,
    )
    write_rows(
        args.report_dir / "source_path_hints_ranked.csv",
        ["rank", "source_path", "hint_count", "sample_addresses"],
        source_path_hints,
    )

    summary = {
        "report_dir": str(args.report_dir),
        "missing_xref_rows": len(missing_xrefs),
        "ranked_missing_xref_targets": len(xref_targets),
        "ranked_missing_xref_sources": len(xref_sources),
        "ranked_instruction_gap_clusters": len(instruction_clusters),
        "ranked_actionable_instruction_gap_clusters": len(actionable_instruction_clusters),
        "ranked_hint_kinds": len(hint_kinds),
        "ranked_source_path_hints": len(source_path_hints),
        "ranked_wpj_source_paths": len(source_paths),
        "top_missing_xref_targets": xref_targets[:10],
        "top_actionable_instruction_gap_clusters": actionable_instruction_clusters[:10],
        "top_hint_kinds": hint_kinds[:10],
        "top_source_path_hints": source_path_hints[:10],
        "outputs": outputs,
    }
    (args.report_dir / "rank_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
