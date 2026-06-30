#!/usr/bin/env python3
"""Run reccmp progress stats and compare them with a committed baseline."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
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

METRICS: tuple[tuple[str, str, str, str], ...] = (
    ("aligned_fun_count", "aligned functions (100%)", "int", "higher"),
    ("paired_fun_count", "paired functions", "int", "higher"),
    ("orig_only_count", "original-only functions", "int", "lower"),
    ("recomp_only_count", "recomp-only functions", "int", "lower"),
    ("not_aligned_vs_original_count", "not aligned vs original", "int", "lower"),
    ("coverage_pct", "function coverage", "pct", "higher"),
    ("aligned_vs_original_pct", "aligned/original", "pct", "higher"),
    ("aligned_vs_paired_pct", "aligned/paired", "pct", "higher"),
    ("avg_matching_pct", "average similarity", "pct", "higher"),
    ("paired_global_count", "paired globals", "int", "higher"),
    ("global_orig_only_count", "global original-only", "int", "lower"),
    ("global_recomp_only_count", "global recomp-only", "int", "lower"),
    ("global_coverage_pct", "global coverage", "pct", "higher"),
    ("paired_non_fun_count", "paired non-functions", "int", "higher"),
    ("non_fun_coverage_pct", "non-function coverage", "pct", "higher"),
    ("dropped_duplicate_address_count", "dropped duplicate addresses", "int", "lower"),
    ("failed_to_match_function_count", "failed-to-match lines", "int", "lower"),
    ("invalid_address_count", "invalid-address lines", "int", "lower"),
)


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    parser.add_argument("--detect-recompiled", action="store_true")
    parser.add_argument("--no-run", action="store_true", help="Parse existing report files only.")
    parser.add_argument(
        "--baseline-file",
        default=str(repo_root / "config" / "reccmp_progress_baseline.json"),
        help="Committed baseline JSON. Relative paths resolve from the repo root.",
    )
    parser.add_argument("--commit-baseline", action="store_true", help="Overwrite the baseline.")
    parser.add_argument("--roadmap-csv", default="reccmp_roadmap.csv")
    parser.add_argument("--report-json", default="reccmp_report.json")
    parser.add_argument("--report-log", default="reccmp_report.log")
    return parser.parse_args()


def git_info() -> dict[str, str]:
    try:
        return {
            "git_branch": subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True
            ).strip(),
            "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "git_commit_date": subprocess.check_output(
                ["git", "log", "-1", "--format=%cI"], text=True
            ).strip(),
        }
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Warning: failed to retrieve git info: {exc}", file=sys.stderr)
        return {}


def resolve_build_path(build_dir: Path, path_arg: str) -> Path:
    path = Path(path_arg)
    return path if path.is_absolute() else build_dir / path


def resolve_repo_path(repo_root: Path, path_arg: str) -> Path:
    path = Path(path_arg)
    return path if path.is_absolute() else repo_root / path


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
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}. See {log_path}")


def pct(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else (numerator / denominator) * 100.0


def parse_optional_int(raw: str) -> int | None:
    value = raw.strip()
    if not value:
        return None
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def parse_roadmap_counts(path: Path) -> dict[str, int]:
    if not path.exists():
        raise FileNotFoundError(f"Missing roadmap CSV: {path}")

    fun_orig: set[int] = set()
    fun_recomp: set[int] = set()
    fun_paired: set[int] = set()
    non_fun_sets: dict[str, dict[str, set[int]]] = {
        row_type: {"orig": set(), "recomp": set(), "paired": set()}
        for row_type in TRACKED_NON_FUNCTION_ROW_TYPES
    }

    with path.open("r", encoding="utf-8", newline="") as fd:
        for row in csv.DictReader(fd):
            row_type = row.get("row_type", "")
            orig_addr = parse_optional_int(row.get("orig_addr", ""))
            recomp_addr = parse_optional_int(row.get("recomp_addr", ""))

            if row_type == FUNCTION_ROW_TYPE:
                if orig_addr is not None:
                    fun_orig.add(orig_addr)
                if recomp_addr is not None:
                    fun_recomp.add(recomp_addr)
                if orig_addr is not None and recomp_addr is not None:
                    fun_paired.add(orig_addr)
                continue

            if row_type in non_fun_sets:
                entry = non_fun_sets[row_type]
                if orig_addr is not None:
                    entry["orig"].add(orig_addr)
                if recomp_addr is not None:
                    entry["recomp"].add(recomp_addr)
                if orig_addr is not None and recomp_addr is not None:
                    entry["paired"].add(orig_addr)

    stats = {
        "original_fun_count": len(fun_orig),
        "recompiled_fun_count": len(fun_recomp),
        "paired_fun_count": len(fun_paired),
        "orig_only_count": max(len(fun_orig) - len(fun_paired), 0),
        "recomp_only_count": max(len(fun_recomp) - len(fun_paired), 0),
    }

    global_orig: set[int] = set()
    global_recomp: set[int] = set()
    global_paired: set[int] = set()
    non_fun_orig: set[int] = set()
    non_fun_recomp: set[int] = set()
    non_fun_paired: set[int] = set()

    for row_type, entry in non_fun_sets.items():
        orig = entry["orig"]
        recomp = entry["recomp"]
        paired = entry["paired"]
        stats[f"original_{row_type}_count"] = len(orig)
        stats[f"recompiled_{row_type}_count"] = len(recomp)
        stats[f"paired_{row_type}_count"] = len(paired)
        stats[f"{row_type}_orig_only_count"] = max(len(orig) - len(paired), 0)
        stats[f"{row_type}_recomp_only_count"] = max(len(recomp) - len(paired), 0)

        non_fun_orig |= orig
        non_fun_recomp |= recomp
        non_fun_paired |= paired
        if row_type in GLOBAL_ROW_TYPES:
            global_orig |= orig
            global_recomp |= recomp
            global_paired |= paired

    stats.update(
        {
            "original_global_count": len(global_orig),
            "recompiled_global_count": len(global_recomp),
            "paired_global_count": len(global_paired),
            "global_orig_only_count": max(len(global_orig) - len(global_paired), 0),
            "global_recomp_only_count": max(len(global_recomp) - len(global_paired), 0),
            "original_non_fun_count": len(non_fun_orig),
            "recompiled_non_fun_count": len(non_fun_recomp),
            "paired_non_fun_count": len(non_fun_paired),
            "non_fun_orig_only_count": max(len(non_fun_orig) - len(non_fun_paired), 0),
            "non_fun_recomp_only_count": max(len(non_fun_recomp) - len(non_fun_paired), 0),
        }
    )
    return stats


# Per-function similarity below/above this delta counts as a real change (not float noise).
FUNCTION_CHANGE_EPS = 1e-4
# Cap how many per-function lines we print before summarizing the rest.
FUNCTION_CHANGE_CAP = 50


def parse_report_functions(path: Path) -> dict[str, dict[str, Any]]:
    """Map each paired original function address -> {matching, name} from the reccmp report."""
    if not path.exists():
        raise FileNotFoundError(f"Missing reccmp JSON report: {path}")

    funcs: dict[str, dict[str, Any]] = {}
    for row in json.loads(path.read_text(encoding="utf-8")).get("data", []):
        address = row.get("address")
        if not address:
            continue
        funcs[address] = {"m": float(row.get("matching", 0.0)), "n": row.get("name", "")}
    return funcs


# Report fields that churn on every rebuild without reflecting a real similarity change.
REPORT_VOLATILE_TOP_KEYS = ("timestamp",)
REPORT_VOLATILE_ROW_KEYS = ("recomp",)


def normalize_report(path: Path) -> dict[str, Any]:
    """Strip volatile fields and sort rows so the committed baseline diffs only on real changes."""
    report = json.loads(path.read_text(encoding="utf-8"))
    normalized = {k: v for k, v in report.items() if k not in REPORT_VOLATILE_TOP_KEYS}
    rows = [
        {k: v for k, v in row.items() if k not in REPORT_VOLATILE_ROW_KEYS}
        for row in report.get("data", [])
    ]
    rows.sort(key=lambda row: parse_optional_int(row.get("address", "")) or 0)
    normalized["data"] = rows
    return normalized


def function_baseline_path(baseline_file: Path) -> Path:
    """Sibling holding the committed reccmp report used for per-function regression diffing.

    This is the raw `reccmp-reccmp --json` output (same schema `parse_report_functions`
    reads from the live build), not a bespoke derived format.
    """
    return baseline_file.with_name(f"{baseline_file.stem}.report.json")


def load_function_baseline(path: Path) -> dict[str, dict[str, Any]] | None:
    if not path.exists():
        return None
    return parse_report_functions(path)


def function_changes(
    curr: dict[str, dict[str, Any]], base: dict[str, dict[str, Any]]
) -> tuple[list[tuple[str, str, float, float]], list[tuple[str, str, float]], int, int]:
    """Return (regressed, unpaired_now, improved_count, newly_paired_count) vs the baseline."""
    regressed: list[tuple[str, str, float, float]] = []
    unpaired_now: list[tuple[str, str, float]] = []
    improved = 0
    newly_paired = 0

    for address, cur in curr.items():
        prev = base.get(address)
        if prev is None:
            newly_paired += 1
            continue
        delta = float(cur["m"]) - float(prev["m"])
        if delta < -FUNCTION_CHANGE_EPS:
            regressed.append((address, cur.get("n", ""), float(prev["m"]), float(cur["m"])))
        elif delta > FUNCTION_CHANGE_EPS:
            improved += 1

    for address, prev in base.items():
        if address not in curr:
            unpaired_now.append((address, prev.get("n", ""), float(prev["m"])))

    regressed.sort(key=lambda item: item[3] - item[2])  # biggest drop first
    unpaired_now.sort(key=lambda item: item[0])
    return regressed, unpaired_now, improved, newly_paired


def print_function_changes(
    curr: dict[str, dict[str, Any]], base: dict[str, dict[str, Any]] | None
) -> None:
    print("")
    print("Function changes vs baseline")
    if base is None:
        print("  no function baseline; run `just stats-commit` to record one")
        return

    regressed, unpaired_now, improved, newly_paired = function_changes(curr, base)
    if not regressed and not unpaired_now:
        print(f"  no regressions ({improved} improved, {newly_paired} newly paired)")
        return

    if unpaired_now:
        print(f"  unpaired now (were paired): {len(unpaired_now)}")
        for address, name, was in unpaired_now[:FUNCTION_CHANGE_CAP]:
            print(f"    - {address} {name} (was {was * 100:.2f}%)")
        if len(unpaired_now) > FUNCTION_CHANGE_CAP:
            print(f"    ... +{len(unpaired_now) - FUNCTION_CHANGE_CAP} more")

    if regressed:
        print(f"  lower similarity: {len(regressed)}")
        for address, name, was, now in regressed[:FUNCTION_CHANGE_CAP]:
            print(
                f"    - {address} {name}: {was * 100:.2f}% -> {now * 100:.2f}% "
                f"({(now - was) * 100:+.2f} pp)"
            )
        if len(regressed) > FUNCTION_CHANGE_CAP:
            print(f"    ... +{len(regressed) - FUNCTION_CHANGE_CAP} more")

    print(f"  ({improved} improved, {newly_paired} newly paired)")


def parse_report_counts(path: Path) -> dict[str, float | int]:
    if not path.exists():
        raise FileNotFoundError(f"Missing reccmp JSON report: {path}")

    rows = json.loads(path.read_text(encoding="utf-8")).get("data", [])
    compared = len(rows)
    total_matching = 0.0
    aligned = 0
    for row in rows:
        matching = float(row.get("matching", 0.0))
        total_matching += matching
        aligned += int(matching >= 1.0)

    return {
        "compared_fun_count": compared,
        "aligned_fun_count": aligned,
        "not_aligned_compared_count": max(compared - aligned, 0),
        "avg_matching_pct": (total_matching / compared) * 100.0 if compared else 0.0,
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


def load_baseline(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def build_entry(args: argparse.Namespace, build_dir: Path) -> dict[str, Any]:
    roadmap_csv = resolve_build_path(build_dir, args.roadmap_csv)
    report_json = resolve_build_path(build_dir, args.report_json)
    report_log = resolve_build_path(build_dir, args.report_log)

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

    noise_log = report_log
    legacy_log = build_dir / "reccmp_run.log"
    if not noise_log.exists() and legacy_log.exists():
        noise_log = legacy_log

    entry: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": args.target,
        **git_info(),
        **parse_roadmap_counts(roadmap_csv),
        **parse_report_counts(report_json),
        **parse_noise_counts(noise_log),
    }
    entry["coverage_pct"] = pct(entry["paired_fun_count"], entry["original_fun_count"])
    entry["aligned_vs_original_pct"] = pct(entry["aligned_fun_count"], entry["original_fun_count"])
    entry["aligned_vs_paired_pct"] = pct(entry["aligned_fun_count"], entry["paired_fun_count"])
    entry["global_coverage_pct"] = pct(entry["paired_global_count"], entry["original_global_count"])
    entry["non_fun_coverage_pct"] = pct(entry["paired_non_fun_count"], entry["original_non_fun_count"])
    entry["not_aligned_vs_original_count"] = max(
        entry["original_fun_count"] - entry["aligned_fun_count"], 0
    )
    return entry


def format_value(value: Any, kind: str) -> str:
    if kind == "pct":
        return f"{float(value):.2f}%"
    return str(int(value))


def format_delta(curr: Any, base: Any, kind: str) -> str:
    delta = float(curr) - float(base)
    if kind == "pct":
        return f"{delta:+.2f} pp"
    return f"{int(delta):+d}"


def metric_changes(
    entry: dict[str, Any], baseline: dict[str, Any] | None
) -> tuple[list[str], list[str], list[str]]:
    if baseline is None:
        return ([], [], [])

    improved: list[str] = []
    worsened: list[str] = []
    changed: list[str] = []
    for key, label, kind, direction in METRICS:
        if key not in entry or key not in baseline:
            continue
        curr = entry[key]
        base = baseline[key]
        if float(curr) == float(base):
            continue
        line = (
            f"{label}: {format_value(base, kind)} -> {format_value(curr, kind)} "
            f"({format_delta(curr, base, kind)})"
        )
        is_better = (float(curr) > float(base)) if direction == "higher" else (float(curr) < float(base))
        (improved if is_better else worsened).append(line)
        changed.append(line)
    return improved, worsened, changed


def print_count_line(label: str, entry: dict[str, Any], baseline: dict[str, Any] | None, key: str) -> None:
    suffix = ""
    if baseline is not None and key in baseline:
        suffix = f" ({format_delta(entry[key], baseline[key], 'int')})"
    print(f"  {label}: {entry[key]}{suffix}")


def print_pct_line(label: str, entry: dict[str, Any], baseline: dict[str, Any] | None, key: str) -> None:
    suffix = ""
    if baseline is not None and key in baseline:
        suffix = f" ({format_delta(entry[key], baseline[key], 'pct')})"
    print(f"  {label}: {float(entry[key]):.2f}%{suffix}")


def print_summary(entry: dict[str, Any], baseline: dict[str, Any] | None, baseline_file: Path) -> None:
    print(f"Target: {entry['target']}")
    print(f"Baseline file: {baseline_file}")
    if baseline is None:
        print("Baseline: missing; run `just stats-commit` after accepting this snapshot.")
    else:
        base_date = baseline.get("timestamp_utc", "unknown")
        base_commit = baseline.get("git_commit", "unknown")[:12]
        print(f"Baseline: {base_date} @ {base_commit}")
    print("")

    print("Counts")
    print_count_line("original functions", entry, baseline, "original_fun_count")
    print_count_line("recompiled functions", entry, baseline, "recompiled_fun_count")
    print_count_line("paired functions", entry, baseline, "paired_fun_count")
    print_count_line("aligned functions (100%)", entry, baseline, "aligned_fun_count")
    print_count_line("not aligned vs original", entry, baseline, "not_aligned_vs_original_count")
    print_count_line("original-only functions", entry, baseline, "orig_only_count")
    print_count_line("recomp-only functions", entry, baseline, "recomp_only_count")
    print("")

    print("Ratios")
    print_pct_line("function coverage", entry, baseline, "coverage_pct")
    print_pct_line("aligned/original", entry, baseline, "aligned_vs_original_pct")
    print_pct_line("aligned/paired", entry, baseline, "aligned_vs_paired_pct")
    print_pct_line("average similarity", entry, baseline, "avg_matching_pct")
    print("")

    print("Globals / non-functions")
    print_count_line("paired globals", entry, baseline, "paired_global_count")
    print_pct_line("global coverage", entry, baseline, "global_coverage_pct")
    print_count_line("paired non-functions", entry, baseline, "paired_non_fun_count")
    print_pct_line("non-function coverage", entry, baseline, "non_fun_coverage_pct")
    for row_type in TRACKED_NON_FUNCTION_ROW_TYPES:
        label = ROW_TYPE_LABELS.get(row_type, row_type)
        original_key = f"original_{row_type}_count"
        paired_key = f"paired_{row_type}_count"
        coverage = pct(entry[paired_key], entry[original_key])
        print(f"  {row_type} ({label}): original {entry[original_key]}, paired {entry[paired_key]}, coverage {coverage:.2f}%")
    print("")

    print("Noise")
    print_count_line("dropped duplicate addresses", entry, baseline, "dropped_duplicate_address_count")
    print_count_line("failed-to-match lines", entry, baseline, "failed_to_match_function_count")
    print_count_line("invalid-address lines", entry, baseline, "invalid_address_count")

    improved, worsened, changed = metric_changes(entry, baseline)
    print("")
    print("Changes vs baseline")
    if baseline is None:
        print("  no baseline")
    elif not changed:
        print("  no tracked metric changes")
    else:
        if improved:
            print("  improved:")
            for line in improved:
                print(f"    + {line}")
        if worsened:
            print("  worsened:")
            for line in worsened:
                print(f"    - {line}")


def main() -> int:
    try:
        args = parse_args()
        repo_root = repo_root_from_file(__file__)
        build_dir = Path(args.build_dir).resolve()
        build_dir.mkdir(parents=True, exist_ok=True)
        baseline_file = resolve_repo_path(repo_root, args.baseline_file)

        baseline = load_baseline(baseline_file)
        func_baseline_file = function_baseline_path(baseline_file)
        func_baseline = load_function_baseline(func_baseline_file)

        entry = build_entry(args, build_dir)
        report_json = resolve_build_path(build_dir, args.report_json)
        curr_funcs = parse_report_functions(report_json)

        print_summary(entry, baseline, baseline_file)
        print_function_changes(curr_funcs, func_baseline)

        if args.commit_baseline:
            write_json_atomic(baseline_file, entry)
            write_json_atomic(func_baseline_file, normalize_report(report_json))
            print("")
            print(f"Committed stats baseline: {baseline_file}")
            print(f"Committed report baseline: {func_baseline_file}")
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
