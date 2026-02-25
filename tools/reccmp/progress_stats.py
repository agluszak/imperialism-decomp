#!/usr/bin/env python3
"""Run reccmp and print progress stats with deltas against the previous run."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.common.repo import repo_root_from_file

FUNCTION_ROW_TYPE = "fun"
GLOBAL_ROW_TYPES = ("dat", "lab", "str", "flo", "wid")
AUX_NON_FUNCTION_ROW_TYPES = ("imp",)
TRACKED_NON_FUNCTION_ROW_TYPES = GLOBAL_ROW_TYPES + AUX_NON_FUNCTION_ROW_TYPES
ROW_TYPE_LABELS = {
    "dat": "data",
    "lab": "labels",
    "str": "strings",
    "flo": "float constants",
    "wid": "wide strings",
    "imp": "imports",
}


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    default_build_dir = repo_root / "build-msvc500"
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(default_build_dir))
    parser.add_argument("--detect-recompiled", action="store_true")
    parser.add_argument(
        "--no-run",
        action="store_true",
        help="Do not run reccmp commands; parse existing report files only.",
    )
    parser.add_argument(
        "--history-file",
        default="reccmp_progress_history.jsonl",
        help="Path relative to --build-dir unless absolute.",
    )
    parser.add_argument(
        "--roadmap-csv",
        default="reccmp_roadmap.csv",
        help="Path relative to --build-dir unless absolute.",
    )
    parser.add_argument(
        "--report-json",
        default="reccmp_report.json",
        help="Path relative to --build-dir unless absolute.",
    )
    parser.add_argument(
        "--report-log",
        default="reccmp_report.log",
        help="Path relative to --build-dir unless absolute.",
    )
    return parser.parse_args()


def resolve_path(build_dir: Path, path_arg: str) -> Path:
    path = Path(path_arg)
    if path.is_absolute():
        return path
    return build_dir / path


def run_logged(cmd: list[str], cwd: Path, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("+ " + " ".join(cmd) + "\n")
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}. See {log_path}"
        )


def pct(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def parse_optional_int(raw: str) -> int | None:
    value = raw.strip()
    if not value:
        return None
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value)


def parse_roadmap_counts(path: Path) -> dict[str, int]:
    if not path.exists():
        raise FileNotFoundError(f"Missing roadmap CSV: {path}")

    fun_orig_addrs: set[int] = set()
    fun_recomp_addrs: set[int] = set()
    fun_paired_orig_addrs: set[int] = set()
    non_fun_sets: dict[str, dict[str, set[int]]] = {
        row_type: {"orig": set(), "recomp": set(), "paired_orig": set()}
        for row_type in TRACKED_NON_FUNCTION_ROW_TYPES
    }

    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            row_type = row.get("row_type", "")
            orig_addr = parse_optional_int(row.get("orig_addr", ""))
            recomp_addr = parse_optional_int(row.get("recomp_addr", ""))

            if row_type == FUNCTION_ROW_TYPE:
                if orig_addr is not None:
                    fun_orig_addrs.add(orig_addr)
                if recomp_addr is not None:
                    fun_recomp_addrs.add(recomp_addr)
                if orig_addr is not None and recomp_addr is not None:
                    fun_paired_orig_addrs.add(orig_addr)
                continue

            if row_type in non_fun_sets:
                entry = non_fun_sets[row_type]
                if orig_addr is not None:
                    entry["orig"].add(orig_addr)
                if recomp_addr is not None:
                    entry["recomp"].add(recomp_addr)
                if orig_addr is not None and recomp_addr is not None:
                    entry["paired_orig"].add(orig_addr)

    paired = len(fun_paired_orig_addrs)
    original = len(fun_orig_addrs)
    recompiled = len(fun_recomp_addrs)
    stats = {
        "original_fun_count": original,
        "recompiled_fun_count": recompiled,
        "paired_fun_count": paired,
        "orig_only_count": max(original - paired, 0),
        "recomp_only_count": max(recompiled - paired, 0),
    }

    global_orig_addrs: set[int] = set()
    global_recomp_addrs: set[int] = set()
    global_paired_orig_addrs: set[int] = set()
    non_fun_orig_addrs: set[int] = set()
    non_fun_recomp_addrs: set[int] = set()
    non_fun_paired_orig_addrs: set[int] = set()

    for row_type, entry in non_fun_sets.items():
        orig_addrs = entry["orig"]
        recomp_addrs = entry["recomp"]
        paired_orig_addrs = entry["paired_orig"]

        stats[f"original_{row_type}_count"] = len(orig_addrs)
        stats[f"recompiled_{row_type}_count"] = len(recomp_addrs)
        stats[f"paired_{row_type}_count"] = len(paired_orig_addrs)
        stats[f"{row_type}_orig_only_count"] = max(len(orig_addrs) - len(paired_orig_addrs), 0)
        stats[f"{row_type}_recomp_only_count"] = max(
            len(recomp_addrs) - len(paired_orig_addrs), 0
        )

        non_fun_orig_addrs |= orig_addrs
        non_fun_recomp_addrs |= recomp_addrs
        non_fun_paired_orig_addrs |= paired_orig_addrs
        if row_type in GLOBAL_ROW_TYPES:
            global_orig_addrs |= orig_addrs
            global_recomp_addrs |= recomp_addrs
            global_paired_orig_addrs |= paired_orig_addrs

    stats["original_global_count"] = len(global_orig_addrs)
    stats["recompiled_global_count"] = len(global_recomp_addrs)
    stats["paired_global_count"] = len(global_paired_orig_addrs)
    stats["global_orig_only_count"] = max(
        len(global_orig_addrs) - len(global_paired_orig_addrs), 0
    )
    stats["global_recomp_only_count"] = max(
        len(global_recomp_addrs) - len(global_paired_orig_addrs), 0
    )

    stats["original_non_fun_count"] = len(non_fun_orig_addrs)
    stats["recompiled_non_fun_count"] = len(non_fun_recomp_addrs)
    stats["paired_non_fun_count"] = len(non_fun_paired_orig_addrs)
    stats["non_fun_orig_only_count"] = max(
        len(non_fun_orig_addrs) - len(non_fun_paired_orig_addrs), 0
    )
    stats["non_fun_recomp_only_count"] = max(
        len(non_fun_recomp_addrs) - len(non_fun_paired_orig_addrs), 0
    )
    return stats


def parse_report_counts(path: Path) -> dict[str, float | int]:
    if not path.exists():
        raise FileNotFoundError(f"Missing reccmp JSON report: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("data", [])
    compared = len(rows)
    aligned = 0
    total_matching = 0.0
    for row in rows:
        matching = float(row.get("matching", 0.0))
        total_matching += matching
        if matching >= 1.0:
            aligned += 1

    avg_matching_pct = (total_matching / compared) * 100.0 if compared else 0.0

    return {
        "compared_fun_count": compared,
        "aligned_fun_count": aligned,
        "not_aligned_compared_count": max(compared - aligned, 0),
        "avg_matching_pct": avg_matching_pct,
    }


def parse_noise_counts(report_log_path: Path) -> dict[str, int]:
    counts = {
        "dropped_duplicate_address_count": 0,
        "failed_to_match_function_count": 0,
        "invalid_address_count": 0,
    }
    if not report_log_path.exists():
        return counts

    with report_log_path.open("r", encoding="utf-8", errors="ignore") as fd:
        for line in fd:
            if "Dropped duplicate address" in line:
                counts["dropped_duplicate_address_count"] += 1
            if "Failed to match function at" in line:
                counts["failed_to_match_function_count"] += 1
            if "Invalid address" in line:
                counts["invalid_address_count"] += 1
    return counts


def load_last_history_entry(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    last: dict[str, Any] | None = None
    with path.open("r", encoding="utf-8") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            last = json.loads(line)
    return last


def append_history(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fd:
        fd.write(json.dumps(entry, sort_keys=True))
        fd.write("\n")


def delta_str(curr: int, prev: dict[str, Any] | None, key: str) -> str:
    if prev is None or key not in prev:
        return " (baseline)"
    delta = curr - int(prev[key])
    if delta > 0:
        return f" (delta +{delta})"
    if delta < 0:
        return f" (delta {delta})"
    return " (delta 0)"


def delta_pp_str(curr: float, prev: dict[str, Any] | None, key: str) -> str:
    if prev is None or key not in prev:
        return " (baseline)"
    delta = curr - float(prev[key])
    if delta > 0:
        return f" (delta +{delta:.2f} pp)"
    if delta < 0:
        return f" (delta {delta:.2f} pp)"
    return " (delta 0.00 pp)"


def progress_signal(curr: dict[str, Any], prev: dict[str, Any] | None) -> tuple[str, str]:
    if prev is None:
        return ("BASELINE", "First recorded run.")

    good = []
    bad = []

    if int(curr["aligned_fun_count"]) > int(prev["aligned_fun_count"]):
        good.append("aligned count increased")
    elif int(curr["aligned_fun_count"]) < int(prev["aligned_fun_count"]):
        bad.append("aligned count decreased")

    if int(curr["paired_fun_count"]) > int(prev["paired_fun_count"]):
        good.append("paired count increased")
    elif int(curr["paired_fun_count"]) < int(prev["paired_fun_count"]):
        bad.append("paired count decreased")

    if (
        "paired_global_count" in curr
        and "paired_global_count" in prev
        and int(curr["paired_global_count"]) > int(prev["paired_global_count"])
    ):
        good.append("paired global count increased")
    elif (
        "paired_global_count" in curr
        and "paired_global_count" in prev
        and int(curr["paired_global_count"]) < int(prev["paired_global_count"])
    ):
        bad.append("paired global count decreased")

    if int(curr["not_aligned_vs_original_count"]) < int(prev["not_aligned_vs_original_count"]):
        good.append("not-aligned-vs-original decreased")
    elif int(curr["not_aligned_vs_original_count"]) > int(prev["not_aligned_vs_original_count"]):
        bad.append("not-aligned-vs-original increased")

    if good and not bad:
        return ("GOOD", "; ".join(good))
    if bad and not good:
        return ("REGRESSION", "; ".join(bad))
    if good and bad:
        return ("MIXED", "; ".join(good + bad))
    return ("STALLED", "No movement in alignment/coverage metrics.")


def main() -> int:
    try:
        args = parse_args()
        build_dir = Path(args.build_dir).resolve()
        build_dir.mkdir(parents=True, exist_ok=True)

        roadmap_csv = resolve_path(build_dir, args.roadmap_csv)
        report_json = resolve_path(build_dir, args.report_json)
        report_log = resolve_path(build_dir, args.report_log)
        history_file = resolve_path(build_dir, args.history_file)

        if not args.no_run:
            if args.detect_recompiled:
                run_logged(
                    ["uv", "run", "reccmp-project", "detect", "--what", "recompiled"],
                    cwd=build_dir,
                    log_path=build_dir / "reccmp_detect.log",
                )
            run_logged(
                ["uv", "run", "reccmp-roadmap", "--target", args.target, "--csv", str(roadmap_csv)],
                cwd=build_dir,
                log_path=build_dir / "reccmp_roadmap.log",
            )
            run_logged(
                [
                    "uv",
                    "run",
                    "reccmp-reccmp",
                    "--target",
                    args.target,
                    "--json",
                    str(report_json),
                    "--json-diet",
                    "--silent",
                    "--no-color",
                ],
                cwd=build_dir,
                log_path=report_log,
            )

        roadmap_stats = parse_roadmap_counts(roadmap_csv)
        report_stats = parse_report_counts(report_json)
        noise_log = report_log
        legacy_log = build_dir / "reccmp_run.log"
        if not noise_log.exists() and legacy_log.exists():
            noise_log = legacy_log
        noise_stats = parse_noise_counts(noise_log)

        now = datetime.now(timezone.utc)
        entry: dict[str, Any] = {
            "timestamp_utc": now.isoformat(),
            "target": args.target,
            **roadmap_stats,
            **report_stats,
            **noise_stats,
        }
        entry["coverage_pct"] = pct(
            int(entry["paired_fun_count"]), int(entry["original_fun_count"])
        )
        entry["aligned_vs_original_pct"] = pct(
            int(entry["aligned_fun_count"]), int(entry["original_fun_count"])
        )
        entry["aligned_vs_paired_pct"] = pct(
            int(entry["aligned_fun_count"]), int(entry["paired_fun_count"])
        )
        entry["global_coverage_pct"] = pct(
            int(entry["paired_global_count"]), int(entry["original_global_count"])
        )
        entry["non_fun_coverage_pct"] = pct(
            int(entry["paired_non_fun_count"]), int(entry["original_non_fun_count"])
        )
        entry["not_aligned_vs_original_count"] = max(
            int(entry["original_fun_count"]) - int(entry["aligned_fun_count"]), 0
        )

        prev = load_last_history_entry(history_file)
        append_history(history_file, entry)
        signal, signal_detail = progress_signal(entry, prev)

        print(f"Target: {args.target}")
        print(f"Build dir: {build_dir}")
        print(f"Timestamp (UTC): {entry['timestamp_utc']}")
        print("")
        print("Counts")
        print(
            f"  original functions: {entry['original_fun_count']}"
            f"{delta_str(int(entry['original_fun_count']), prev, 'original_fun_count')}"
        )
        print(
            f"  recompiled functions: {entry['recompiled_fun_count']}"
            f"{delta_str(int(entry['recompiled_fun_count']), prev, 'recompiled_fun_count')}"
        )
        print(
            f"  paired functions: {entry['paired_fun_count']}"
            f"{delta_str(int(entry['paired_fun_count']), prev, 'paired_fun_count')}"
        )
        print(
            f"  aligned functions (100%): {entry['aligned_fun_count']}"
            f"{delta_str(int(entry['aligned_fun_count']), prev, 'aligned_fun_count')}"
        )
        print(
            f"  not aligned vs original: {entry['not_aligned_vs_original_count']}"
            f"{delta_str(int(entry['not_aligned_vs_original_count']), prev, 'not_aligned_vs_original_count')}"
        )
        print(
            f"  original-only (unpaired): {entry['orig_only_count']}"
            f"{delta_str(int(entry['orig_only_count']), prev, 'orig_only_count')}"
        )
        print(
            f"  recomp-only (unpaired): {entry['recomp_only_count']}"
            f"{delta_str(int(entry['recomp_only_count']), prev, 'recomp_only_count')}"
        )
        print("")
        print("Globals / non-function coverage")
        print(
            f"  original globals (dat/lab/str/flo/wid): {entry['original_global_count']}"
            f"{delta_str(int(entry['original_global_count']), prev, 'original_global_count')}"
        )
        print(
            f"  recompiled globals (dat/lab/str/flo/wid): {entry['recompiled_global_count']}"
            f"{delta_str(int(entry['recompiled_global_count']), prev, 'recompiled_global_count')}"
        )
        print(
            f"  paired globals (dat/lab/str/flo/wid): {entry['paired_global_count']}"
            f"{delta_str(int(entry['paired_global_count']), prev, 'paired_global_count')}"
        )
        print(
            f"  global original-only (unpaired): {entry['global_orig_only_count']}"
            f"{delta_str(int(entry['global_orig_only_count']), prev, 'global_orig_only_count')}"
        )
        print(
            f"  global recomp-only (unpaired): {entry['global_recomp_only_count']}"
            f"{delta_str(int(entry['global_recomp_only_count']), prev, 'global_recomp_only_count')}"
        )
        print(
            f"  non-function total coverage (including imports): {entry['non_fun_coverage_pct']:.2f}%"
            f"{delta_pp_str(float(entry['non_fun_coverage_pct']), prev, 'non_fun_coverage_pct')}"
        )
        print(
            f"  global coverage (paired/original): {entry['global_coverage_pct']:.2f}%"
            f"{delta_pp_str(float(entry['global_coverage_pct']), prev, 'global_coverage_pct')}"
        )
        for row_type in TRACKED_NON_FUNCTION_ROW_TYPES:
            label = ROW_TYPE_LABELS.get(row_type, row_type)
            original_key = f"original_{row_type}_count"
            paired_key = f"paired_{row_type}_count"
            recompiled_key = f"recompiled_{row_type}_count"
            type_coverage = pct(int(entry[paired_key]), int(entry[original_key]))
            print(
                f"  {row_type} ({label}): "
                f"original {entry[original_key]}{delta_str(int(entry[original_key]), prev, original_key)}, "
                f"paired {entry[paired_key]}{delta_str(int(entry[paired_key]), prev, paired_key)}, "
                f"recompiled {entry[recompiled_key]}{delta_str(int(entry[recompiled_key]), prev, recompiled_key)}, "
                f"coverage {type_coverage:.2f}%"
            )
        print("")
        print("Ratios")
        print(
            f"  coverage (paired/original): {entry['coverage_pct']:.2f}%"
            f"{delta_pp_str(float(entry['coverage_pct']), prev, 'coverage_pct')}"
        )
        print(
            f"  aligned/original: {entry['aligned_vs_original_pct']:.2f}%"
            f"{delta_pp_str(float(entry['aligned_vs_original_pct']), prev, 'aligned_vs_original_pct')}"
        )
        print(
            f"  aligned/paired: {entry['aligned_vs_paired_pct']:.2f}%"
            f"{delta_pp_str(float(entry['aligned_vs_paired_pct']), prev, 'aligned_vs_paired_pct')}"
        )
        print(
            f"  average similarity of compared functions: {entry['avg_matching_pct']:.2f}%"
            f"{delta_pp_str(float(entry['avg_matching_pct']), prev, 'avg_matching_pct')}"
        )
        print("")
        print("Signal")
        print(f"  {signal}: {signal_detail}")
        print("")
        print("Noise (from reccmp output)")
        print(f"  dropped duplicate addresses: {entry['dropped_duplicate_address_count']}")
        print(f"  failed-to-match lines: {entry['failed_to_match_function_count']}")
        print(f"  invalid-address lines: {entry['invalid_address_count']}")
        print("")
        print(f"History file: {history_file}")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
