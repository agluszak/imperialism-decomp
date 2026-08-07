#!/usr/bin/env python3
"""Run reccmp progress stats and compare them with a committed baseline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import logging
import os
import subprocess
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from reccmp.compare import Compare
from reccmp.compare.report import (
    ReccmpComparedEntity,
    ReccmpStatusReport,
    serialize_reccmp_report,
)
from reccmp.project.detect import RecCmpProject
from reccmp.types import EntityType

from tools.common.function_baseline import (
    load_function_baseline,
    write_function_baseline_atomic,
)
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file
from tools.common.report_score import effective_matching
from tools.common.template_aliases import (
    CLASS_DUPLICATE_EMISSION,
    CLASS_FOLDED_SYMBOL_GROUP,
    load_aliases,
)
from tools.stubgen import ILT_THUNK_RANGE, compute_stub_rows

FUNCTION_ROW_TYPE = "function"
REPORT_CACHE_VERSION = 2
REPORT_CACHE_FILE = "reccmp_report.inputs.json"
GLOBAL_ROW_TYPES = ("data", "label", "string", "float", "widechar", "vtable")
AUX_NON_FUNCTION_ROW_TYPES = ("import", "import_thunk")
TRACKED_NON_FUNCTION_ROW_TYPES = GLOBAL_ROW_TYPES + AUX_NON_FUNCTION_ROW_TYPES
EXPECTED_UNPAIRED_ROW_TYPES = frozenset(("label", "float"))
ROW_TYPE_LABELS = {
    "data": "data",
    "label": "labels",
    "string": "strings",
    "float": "float constants",
    "widechar": "wide strings",
    "vtable": "vtables",
    "import": "imports",
    "import_thunk": "import thunks",
}
PAIRING_STATES = frozenset(("paired", "unexplained", "recomp_only", "alias", "duplicate"))


METRICS: tuple[tuple[str, str, str, str], ...] = (
    ("exact_fun_count", "exact functions (100%)", "int", "higher"),
    ("paired_fun_count", "address-paired functions", "int", "higher"),
    ("compared_fun_count", "implemented paired functions", "int", "higher"),
    ("orig_only_count", "original-only functions", "int", "lower"),
    ("template_alias_recognized_count", "recognized duplicate template bodies", "int", "higher"),
    ("template_canonical_paired_count", "template canonical bodies paired", "int", "higher"),
    ("recomp_only_count", "recomp-only functions", "int", "lower"),
    ("not_exact_vs_original_count", "not exact vs original", "int", "lower"),
    ("address_pairing_coverage_pct", "address pairing coverage", "pct", "higher"),
    ("implementation_coverage_pct", "implementation coverage", "pct", "higher"),
    ("exact_vs_original_pct", "exact/original", "pct", "higher"),
    ("exact_vs_implemented_pct", "exact/implemented", "pct", "higher"),
    ("size_weighted_matching_pct", "size-weighted similarity", "pct", "higher"),
    ("ui_factory_weighted_pct", "generated UI factory fidelity", "pct", "higher"),
    ("avg_matching_pct", "average similarity (unweighted)", "pct", "higher"),
    ("paired_global_count", "paired globals", "int", "higher"),
    ("global_orig_only_count", "global original-only", "int", "lower"),
    ("global_recomp_only_count", "global recomp-only", "int", "lower"),
    ("global_coverage_pct", "global coverage", "pct", "higher"),
    ("paired_non_fun_count", "paired non-functions", "int", "higher"),
    ("non_fun_coverage_pct", "raw non-function coverage", "pct", "higher"),
    ("actionable_non_fun_coverage_pct", "actionable non-function coverage", "pct", "higher"),
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
        "--ui-codegen-gate",
        action="store_true",
        help="Fail if a generated UI factory is unpaired or below its baseline.",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help=(
            "Fail if any previously paired non-stub function becomes unpaired or "
            "decreases beyond the score epsilon."
        ),
    )
    parser.add_argument(
        "--baseline-file",
        default=str(repo_root / "config" / "baselines" / "reccmp_progress_baseline.json"),
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
    except Exception:
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


def build_progress_report(
    filename: str, compared: Iterable[ReccmpComparedEntity]
) -> ReccmpStatusReport:
    """Build the complete report used for progress accounting.

    ``report.ignore_functions`` is a presentation filter for normal reccmp CLI
    reports. Progress baselines must include every comparable entity, otherwise a
    symbol rename or ignore-list refresh silently rewrites historical progress.
    """
    report = ReccmpStatusReport(filename=filename)
    for match in compared:
        report.add_match(match)
    return report


def run_progress_report(
    target_id: str, build_dir: Path, output: Path, log_path: Path
) -> None:
    """Write a complete diet report without applying presentation ignore lists."""
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"+ complete reccmp progress report --target {target_id}\n")
        handler = logging.StreamHandler(log)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        try:
            with redirect_stdout(log), redirect_stderr(log):
                project = RecCmpProject.from_directory(build_dir)
                target = project.get(target_id)
                compare = Compare.from_target(target)
                report = build_progress_report(
                    target.original_path.name,
                    compare.compare_all(include_diff=False, include_exact_diff=False),
                )
        finally:
            root_logger.removeHandler(handler)

    output.write_text(
        serialize_reccmp_report(report, diff_included=False) + "\n",
        encoding="utf-8",
    )


def pct(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else (numerator / denominator) * 100.0


def parse_optional_int(raw: str) -> int | None:
    value = raw.strip()
    if not value:
        return None
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def parse_roadmap_counts(path: Path) -> dict[str, int]:
    """Count typed roadmap entities without lossy three-letter type aliases.

    ``pairing_state`` is part of the project roadmap schema.  Current roadmap
    generation emits paired/unexplained/recomp_only.  Alias-aware reccmp
    versions may additionally emit alias/duplicate; those states are accepted
    now so progress accounting does not have to infer equivalence from names.
    """
    if not path.exists():
        raise FileNotFoundError(f"Missing roadmap CSV: {path}")

    function_rows: dict[str, set[int]] = {
        state: set() for state in PAIRING_STATES
    }
    non_fun_sets: dict[str, dict[str, set[int]]] = {
        row_type: {state: set() for state in PAIRING_STATES}
        for row_type in TRACKED_NON_FUNCTION_ROW_TYPES
    }
    raw_orig: dict[str, set[int]] = {FUNCTION_ROW_TYPE: set()}
    raw_recomp: dict[str, set[int]] = {FUNCTION_ROW_TYPE: set()}
    for row_type in TRACKED_NON_FUNCTION_ROW_TYPES:
        raw_orig[row_type] = set()
        raw_recomp[row_type] = set()

    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd)
        required = {"row_type", "pairing_state", "orig_addr", "recomp_addr"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"Roadmap CSV lacks typed schema columns: {', '.join(sorted(missing))}. "
                "Regenerate it with the repository roadmap target."
            )
        for line_no, row in enumerate(reader, 2):
            row_type = (row.get("row_type") or "").strip().lower()
            if row_type not in raw_orig:
                continue
            state = (row.get("pairing_state") or "").strip().lower()
            if state not in PAIRING_STATES:
                raise ValueError(f"Roadmap CSV line {line_no}: invalid pairing_state {state!r}")
            orig_addr = parse_optional_int(row.get("orig_addr", ""))
            recomp_addr = parse_optional_int(row.get("recomp_addr", ""))
            if orig_addr is not None:
                raw_orig[row_type].add(orig_addr)
            if recomp_addr is not None:
                raw_recomp[row_type].add(recomp_addr)
            target = function_rows if row_type == FUNCTION_ROW_TYPE else non_fun_sets[row_type]
            identity = orig_addr if orig_addr is not None else recomp_addr
            if identity is not None:
                target[state].add(identity)

    # Function aliases use the reviewed equivalence table until reccmp emits
    # their state directly.  Explicit typed-roadmap states always win.
    duplicate_aliases, duplicate_errors = load_aliases(
        equivalence_class=CLASS_DUPLICATE_EMISSION
    )
    folded_aliases, folded_errors = load_aliases(
        equivalence_class=CLASS_FOLDED_SYMBOL_GROUP
    )
    aliases = {**duplicate_aliases, **folded_aliases}
    for err in duplicate_errors + folded_errors:
        print(f"WARNING template_aliases.csv: {err}")
    paired_functions = function_rows["paired"]
    recognized = {
        alias for alias, canonical in aliases.items()
        if alias in raw_orig[FUNCTION_ROW_TYPE]
        and alias in function_rows["unexplained"]
        and canonical in paired_functions
    }
    function_rows["unexplained"] -= recognized
    function_rows["duplicate"] |= recognized
    canonical_paired = {c for c in aliases.values() if c in paired_functions}

    stats = {
        "original_fun_count": len(raw_orig[FUNCTION_ROW_TYPE]),
        "recompiled_fun_count": len(raw_recomp[FUNCTION_ROW_TYPE]),
        "paired_fun_count": len(paired_functions),
        "orig_only_count": len(function_rows["unexplained"]),
        "recomp_only_count": len(function_rows["recomp_only"]),
        "template_alias_recognized_count": len(recognized),
        "template_canonical_paired_count": len(canonical_paired),
    }

    global_orig = global_recomp = global_covered = 0
    non_fun_orig = non_fun_recomp = non_fun_covered = 0
    actionable_orig = actionable_covered = actionable_unexplained = 0

    for row_type, states in non_fun_sets.items():
        orig = raw_orig[row_type]
        recomp = raw_recomp[row_type]
        covered = states["paired"] | states["alias"] | states["duplicate"]
        expected = states["unexplained"] if row_type in EXPECTED_UNPAIRED_ROW_TYPES else set()
        unexplained = set() if row_type in EXPECTED_UNPAIRED_ROW_TYPES else states["unexplained"]
        stats[f"original_{row_type}_count"] = len(orig)
        stats[f"recompiled_{row_type}_count"] = len(recomp)
        stats[f"paired_{row_type}_count"] = len(states["paired"])
        stats[f"alias_{row_type}_count"] = len(states["alias"])
        stats[f"duplicate_{row_type}_count"] = len(states["duplicate"])
        stats[f"unexplained_{row_type}_count"] = len(unexplained)
        stats[f"expected_unpaired_{row_type}_count"] = len(expected)
        stats[f"{row_type}_recomp_only_count"] = len(states["recomp_only"])

        non_fun_orig += len(orig)
        non_fun_recomp += len(recomp)
        non_fun_covered += len(covered)
        if row_type not in EXPECTED_UNPAIRED_ROW_TYPES:
            actionable_orig += len(orig)
            actionable_covered += len(covered)
            actionable_unexplained += len(unexplained)
        if row_type in GLOBAL_ROW_TYPES:
            global_orig += len(orig)
            global_recomp += len(recomp)
            global_covered += len(covered)

    stats.update({
        "original_global_count": global_orig,
        "recompiled_global_count": global_recomp,
        "paired_global_count": global_covered,
        "global_orig_only_count": global_orig - global_covered,
        "global_recomp_only_count": max(global_recomp - global_covered, 0),
        "original_non_fun_count": non_fun_orig,
        "recompiled_non_fun_count": non_fun_recomp,
        "paired_non_fun_count": non_fun_covered,
        "non_fun_orig_only_count": non_fun_orig - non_fun_covered,
        "non_fun_recomp_only_count": max(non_fun_recomp - non_fun_covered, 0),
        "actionable_non_fun_count": actionable_orig,
        "actionable_non_fun_covered_count": actionable_covered,
        "actionable_non_fun_unexplained_count": actionable_unexplained,
    })
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
        row_type = row.get("type")
        if row_type is not None and row_type != int(EntityType.FUNCTION):
            continue
        if row.get("stub", False):
            continue
        address = row.get("address")
        if not address:
            continue
        funcs[address] = {
            "m": effective_matching(row),
            "n": str(row.get("name") or "").rstrip(),
        }
    return funcs


def generated_stub_report_errors(
    path: Path, stub_rows: Iterable[tuple[int, str, str]]
) -> list[str]:
    """Require every annotated generated placeholder to be reported as a stub.

    ILT entries are generated linker-thunk definitions, not placeholder entities.
    They intentionally carry no marker because annotating an ILT address prevents
    reccmp from resolving the thunk to its target.
    """
    if not path.exists():
        raise FileNotFoundError(f"Missing reccmp JSON report: {path}")

    expected = {
        address
        for address, _name, _prototype in stub_rows
        if address not in ILT_THUNK_RANGE
    }
    reported: dict[int, bool] = {}
    for row in json.loads(path.read_text(encoding="utf-8")).get("data", []):
        address = row.get("address")
        if not address:
            continue
        try:
            reported[int(str(address), 16)] = bool(row.get("stub", False))
        except ValueError:
            continue

    missing = sorted(expected - reported.keys())
    not_stub = sorted(
        address for address in expected if address in reported and not reported[address]
    )
    errors = [
        f"0x{address:08x}: generated placeholder missing from report"
        for address in missing
    ]
    errors.extend(
        f"0x{address:08x}: generated placeholder reported without stub=true"
        for address in not_stub
    )
    return errors


def ui_codegen_regressions(
    addresses: Iterable[int],
    current: dict[str, dict[str, Any]],
    baseline: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for address in addresses:
        key = hex(address)
        label = f"0x{address:08x}"
        before = baseline.get(key)
        after = current.get(key)
        if before is None:
            errors.append(f"{label}: missing from committed baseline")
        elif after is None:
            errors.append(f"{label}: generated function is not paired")
        elif float(after["m"]) < float(before["m"]) - FUNCTION_CHANGE_EPS:
            errors.append(
                f"{label}: similarity regressed "
                f"{float(before['m']) * 100:.4f}% -> {float(after['m']) * 100:.4f}%"
            )
    return errors


def function_baseline_path(baseline_file: Path) -> Path:
    """Sibling holding the compact per-function score snapshot."""
    return baseline_file.with_name(f"{baseline_file.stem}.functions.csv")


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


def baseline_provenance_error(
    entry: dict[str, Any], baseline: dict[str, Any] | None, working_tree_clean: bool
) -> str | None:
    """Reject a stale committed snapshot while allowing an in-progress dirty tree."""
    if not working_tree_clean or baseline is None:
        return None
    expected = baseline.get("source_model_fingerprint")
    actual = entry.get("source_model_fingerprint")
    if not isinstance(expected, str):
        return "committed stats baseline lacks source_model_fingerprint"
    if expected != actual:
        return (
            "committed stats baseline source_model_fingerprint does not describe "
            "the current clean source/model/build inputs"
        )
    return None


def tracked_worktree_is_clean(repo_root: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return not result.stdout.strip()


def print_function_changes(
    curr: dict[str, dict[str, Any]], base: dict[str, dict[str, Any]] | None
) -> None:
    print("")
    print("Function changes vs baseline")
    if base is None:
        print("  no function baseline; run `just stats-baseline-update` to record one")
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


def load_function_sizes(build_dir: Path) -> dict[int, int]:
    """address -> original byte size, from the generated symbol table.

    Falls back to config/original_entities.csv when the build dir has no
    generated table yet (e.g. --no-run on a fresh checkout).
    """
    candidates = [
        build_dir / "generated" / "symbols.csv",
        repo_root_from_file(__file__) / "config" / "original_entities.csv",
    ]
    sizes: dict[int, int] = {}
    for path in candidates:
        if not path.exists():
            continue
        for row in read_pipe_rows(path):
            if (row.get("type") or "").strip().lower() != "function":
                continue
            try:
                sizes[int((row.get("address") or "").strip(), 16)] = int(
                    (row.get("size") or "").strip()
                )
            except ValueError:
                continue
        if sizes:
            break
    return sizes


def parse_report_counts(path: Path, sizes: dict[int, int] | None = None) -> dict[str, float | int]:
    if not path.exists():
        raise FileNotFoundError(f"Missing reccmp JSON report: {path}")

    rows = [
        row
        for row in json.loads(path.read_text(encoding="utf-8")).get("data", [])
        if (row.get("type") is None or row.get("type") == int(EntityType.FUNCTION))
        and not row.get("stub", False)
    ]
    compared = len(rows)
    total_matching = 0.0
    exact = 0
    # Size-weighted similarity: sum(matching * original size) / sum(original size).
    # The unweighted mean over-counts tiny bodies (a 12-byte thunk moves it as much
    # as a 5KB dispatcher); the weighted form tracks matched code volume. Rows with
    # no known original size fall back to weight 1 so they still participate.
    weighted_sum = 0.0
    weight_total = 0.0
    for row in rows:
        matching = effective_matching(row)
        total_matching += matching
        exact += int(matching >= 1.0)
        weight = 1
        if sizes is not None:
            try:
                weight = max(sizes.get(int(str(row.get("address")), 16), 1), 1)
            except (TypeError, ValueError):
                weight = 1
        weighted_sum += matching * weight
        weight_total += weight

    return {
        "compared_fun_count": compared,
        "exact_fun_count": exact,
        "not_exact_compared_count": max(compared - exact, 0),
        "avg_matching_pct": (total_matching / compared) * 100.0 if compared else 0.0,
        "size_weighted_matching_pct": (weighted_sum / weight_total) * 100.0 if weight_total else 0.0,
    }


def ui_factory_fidelity(
    report_json: Path, sizes: dict[int, int] | None, repo_root: Path
) -> dict[str, Any]:
    """Size-weighted match across the generated UI factory set.

    The 17 recipe factories are ~18% of all paired bytes and by far the largest single
    score deficit, but the only thing watching them was a per-function ratchet ("do not
    get worse") -- the aggregate number itself was recomputed by hand whenever someone
    asked (imperialism-decomp-wqfq). Tracking it as a first-class metric puts it in the
    committed baseline and in every precommit diff, so the deficit has a visible owner
    and any drift shows up next to the other aggregates.
    """
    try:
        from tools.ui_codegen import load_recipes

        addresses = {recipe.address for recipe in load_recipes(repo_root)}
    except Exception:  # pragma: no cover - recipes are optional for this metric
        return {}
    if not addresses:
        return {}
    functions = parse_report_functions(report_json)
    weighted_sum = 0.0
    weight_total = 0.0
    paired = 0
    for address in addresses:
        row = functions.get(hex(address))
        if row is None:
            continue
        paired += 1
        weight = max((sizes or {}).get(address, 1), 1)
        weighted_sum += float(row["m"]) * weight
        weight_total += weight
    return {
        "ui_factory_count": len(addresses),
        "ui_factory_paired_count": paired,
        "ui_factory_weighted_pct": (weighted_sum / weight_total) * 100.0 if weight_total else 0.0,
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


POLICY_BASELINE_APPROVAL_ENV = "ALLOW_POLICY_BASELINE_UPDATE"


def clamp_stub_count_ratchet(
    entry: dict[str, Any], baseline: dict[str, Any] | None
) -> str | None:
    """Keep the stub-count ratchet armed when the full snapshot is rewritten.

    `stub_count` is a policy ratchet living inside an observations file: check_stub_count
    FAILS a rise because a rise means a marker-less owner (DYNCREATE GetRuntimeClass,
    scalar deleting dtor, name-paired method) lost its claim and would be re-stubbed.
    The commit policy requires stats-baseline-update before every commit, so carrying a
    raised count into the snapshot re-arms the ratchet at the new height in the very
    commit that raised it -- the gate can then never fire on the change that caused it,
    and `stub-count-gate-update`'s explicit approval is bypassed entirely.

    So a rise is dropped here (the lower baseline value is preserved, the gate stays red)
    unless the same approval the `-update` targets demand is present. A fall ratchets
    down as usual. Returns a message to print, or None when nothing was held back.
    """
    if baseline is None or "stub_count" not in baseline or "stub_count" not in entry:
        return None
    previous = int(baseline["stub_count"])
    current = int(entry["stub_count"])
    if current <= previous:
        return None
    if os.environ.get(POLICY_BASELINE_APPROVAL_ENV) == "1":
        return (
            f"Stub-count ratchet RAISED with {POLICY_BASELINE_APPROVAL_ENV}=1: "
            f"{previous} -> {current} (+{current - previous})."
        )
    entry["stub_count"] = previous
    return (
        f"Stub-count ratchet held at {previous} (observed {current}, +{current - previous}).\n"
        "  A rise means stubs would be regenerated for addresses that lost their claim,\n"
        "  so the snapshot does NOT re-baseline it and `just stub-count-gate` stays red.\n"
        "  Find what got un-claimed and restore the marker/claim row. If the rise really\n"
        f"  is intended, bless it explicitly: {POLICY_BASELINE_APPROVAL_ENV}=1 "
        "just stub-count-gate-update."
    )


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_path_label(repo_root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(repo_root).as_posix()
    except ValueError:
        return str(resolved)


def report_input_hashes(
    repo_root: Path, build_dir: Path, target_id: str
) -> dict[str, str]:
    project = RecCmpProject.from_directory(build_dir)
    target = project.get(target_id)
    paths = {
        repo_root / "pyproject.toml",
        repo_root / "uv.lock",
        repo_root / "reccmp-project.yml",
        repo_root / "reccmp-user.yml",
        build_dir / "reccmp-build.yml",
        Path(__file__),
        target.original_path,
        target.recompiled_path,
        target.recompiled_pdb,
        *target.data_sources,
        *target.equivalence_groups,
    }
    for source_root in target.source_paths:
        paths.update(path for path in source_root.rglob("*") if path.is_file())
    hashes = {
        _cache_path_label(repo_root, path): _file_sha256(path)
        for path in sorted(paths, key=lambda item: str(item.resolve()))
    }
    # pyproject/uv.lock cover pin bumps, but not what is actually installed
    # (e.g. a temporary `uv pip install -e` of the reccmp fork). Stamp the
    # installed distribution so switching pinned <-> editable invalidates.
    hashes["installed:reccmp"] = hashlib.sha256(
        _reccmp_dist_stamp().encode("utf-8")
    ).hexdigest()
    return hashes


def _reccmp_dist_stamp() -> str:
    """Identity of the installed reccmp distribution (version + install origin)."""
    try:
        dist = importlib.metadata.distribution("reccmp")
    except importlib.metadata.PackageNotFoundError:
        return "absent"
    direct_url = dist.read_text("direct_url.json") or ""
    return f"{dist.version}|{direct_url}"


def report_cache_is_current(
    cache_path: Path,
    target_id: str,
    inputs: dict[str, str],
    outputs: dict[str, Path],
) -> bool:
    if not cache_path.is_file() or any(not path.is_file() for path in outputs.values()):
        return False
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if (
        cache.get("format_version") != REPORT_CACHE_VERSION
        or cache.get("target") != target_id
        or cache.get("inputs") != inputs
    ):
        return False
    return cache.get("outputs") == {
        name: _file_sha256(path) for name, path in outputs.items()
    }


def write_report_cache(
    cache_path: Path,
    target_id: str,
    inputs: dict[str, str],
    outputs: dict[str, Path],
) -> None:
    write_json_atomic(
        cache_path,
        {
            "format_version": REPORT_CACHE_VERSION,
            "target": target_id,
            "inputs": inputs,
            "outputs": {name: _file_sha256(path) for name, path in outputs.items()},
        },
    )


def build_entry(args: argparse.Namespace, build_dir: Path) -> dict[str, Any]:
    roadmap_csv = resolve_build_path(build_dir, args.roadmap_csv)
    report_json = resolve_build_path(build_dir, args.report_json)
    report_log = resolve_build_path(build_dir, args.report_log)

    repo_root = repo_root_from_file(__file__)
    inputs = report_input_hashes(repo_root, build_dir, args.target)
    if not args.no_run:
        if args.detect_recompiled:
            run_logged(
                ["uv", "run", "reccmp-project", "detect", "--what", "recompiled"],
                cwd=build_dir,
                log_path=build_dir / "reccmp_detect.log",
            )
        outputs = {
            "roadmap_csv": roadmap_csv,
            "report_json": report_json,
            "report_log": report_log,
        }
        cache_path = build_dir / REPORT_CACHE_FILE
        if report_cache_is_current(cache_path, args.target, inputs, outputs):
            print("Reusing full reccmp progress report: verified input and output hashes")
        else:
            run_logged(
                [
                    "uv",
                    "run",
                    "python",
                    "-m",
                    str(repo_root_from_file(__file__) / "tools" / "reccmp" / "typed_roadmap.py"),
                    "--target",
                    args.target,
                    "--csv",
                    str(roadmap_csv),
                ],
                cwd=build_dir,
                log_path=build_dir / "reccmp_roadmap.log",
            )
            run_progress_report(args.target, build_dir, report_json, report_log)
            write_report_cache(cache_path, args.target, inputs, outputs)

    noise_log = report_log
    legacy_log = build_dir / "reccmp_run.log"
    if not noise_log.exists() and legacy_log.exists():
        noise_log = legacy_log

    entry: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": args.target,
        "source_model_fingerprint": hashlib.sha256(
            json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        **git_info(),
        **parse_roadmap_counts(roadmap_csv),
        **parse_report_counts(report_json, load_function_sizes(build_dir)),
        **parse_noise_counts(noise_log),
        **ui_factory_fidelity(report_json, load_function_sizes(build_dir), repo_root_from_file(__file__)),
    }
    # Generated-stub count (formerly config/baselines/stub_count_baseline.json): the
    # stub set the generator would emit (symbols.csv function rows minus source-claimed
    # addresses). A rising count is the tell for accidental un-claiming; the
    # stub-count-gate ratchets it against this same field. Needs no build.
    stub_rows = compute_stub_rows(repo_root_from_file(__file__))
    stub_errors = generated_stub_report_errors(report_json, stub_rows)
    if stub_errors:
        preview = "\n".join(f"  - {error}" for error in stub_errors[:50])
        remainder = len(stub_errors) - 50
        if remainder > 0:
            preview += f"\n  ... +{remainder} more"
        raise RuntimeError(f"generated placeholder report invariant failed:\n{preview}")
    entry["stub_count"] = len(stub_rows)
    entry["address_pairing_coverage_pct"] = pct(
        entry["paired_fun_count"], entry["original_fun_count"]
    )
    entry["implementation_coverage_pct"] = pct(
        entry["compared_fun_count"], entry["original_fun_count"]
    )
    entry["exact_vs_original_pct"] = pct(entry["exact_fun_count"], entry["original_fun_count"])
    entry["exact_vs_implemented_pct"] = pct(
        entry["exact_fun_count"], entry["compared_fun_count"]
    )
    entry["global_coverage_pct"] = pct(entry["paired_global_count"], entry["original_global_count"])
    entry["non_fun_coverage_pct"] = pct(entry["paired_non_fun_count"], entry["original_non_fun_count"])
    entry["actionable_non_fun_coverage_pct"] = pct(
        entry["actionable_non_fun_covered_count"], entry["actionable_non_fun_count"]
    )
    entry["not_exact_vs_original_count"] = max(
        entry["original_fun_count"] - entry["exact_fun_count"], 0
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
        print("Baseline: missing; run `just stats-baseline-update` after accepting this snapshot.")
    else:
        base_date = baseline.get("timestamp_utc", "unknown")
        base_commit = baseline.get("git_commit", "unknown")[:12]
        print(f"Baseline: {base_date} @ {base_commit}")
    print("")

    print("Counts")
    print_count_line("original functions", entry, baseline, "original_fun_count")
    print_count_line("recompiled functions", entry, baseline, "recompiled_fun_count")
    print_count_line("address-paired functions", entry, baseline, "paired_fun_count")
    print_count_line("implemented paired functions", entry, baseline, "compared_fun_count")
    print_count_line("exact functions (100%)", entry, baseline, "exact_fun_count")
    print_count_line("not exact vs original", entry, baseline, "not_exact_vs_original_count")
    print_count_line("original-only functions", entry, baseline, "orig_only_count")
    print_count_line("recognized duplicate template bodies", entry, baseline,
                     "template_alias_recognized_count")
    print_count_line("template canonical bodies paired", entry, baseline,
                     "template_canonical_paired_count")
    print_count_line("recomp-only functions", entry, baseline, "recomp_only_count")
    print("")

    print("Ratios")
    print_pct_line(
        "address pairing coverage", entry, baseline, "address_pairing_coverage_pct"
    )
    print_pct_line(
        "implementation coverage", entry, baseline, "implementation_coverage_pct"
    )
    print_pct_line("exact/original", entry, baseline, "exact_vs_original_pct")
    print_pct_line("exact/implemented", entry, baseline, "exact_vs_implemented_pct")
    print_pct_line("size-weighted similarity", entry, baseline, "size_weighted_matching_pct")
    print_pct_line("average similarity (unweighted)", entry, baseline, "avg_matching_pct")
    if "ui_factory_weighted_pct" in entry:
        print_pct_line(
            f"generated UI factories ({entry.get('ui_factory_paired_count', 0)}"
            f"/{entry.get('ui_factory_count', 0)} paired)",
            entry, baseline, "ui_factory_weighted_pct",
        )
    print("")

    print("Globals / non-functions")
    print_count_line("paired globals", entry, baseline, "paired_global_count")
    print_pct_line("global coverage", entry, baseline, "global_coverage_pct")
    print_count_line("covered non-functions (paired/alias/duplicate)", entry, baseline, "paired_non_fun_count")
    print_pct_line("raw non-function coverage", entry, baseline, "non_fun_coverage_pct")
    print_pct_line("actionable non-function coverage", entry, baseline,
                   "actionable_non_fun_coverage_pct")
    for row_type in TRACKED_NON_FUNCTION_ROW_TYPES:
        label = ROW_TYPE_LABELS.get(row_type, row_type)
        original = entry[f"original_{row_type}_count"]
        paired = entry[f"paired_{row_type}_count"]
        aliases = entry[f"alias_{row_type}_count"]
        duplicates = entry[f"duplicate_{row_type}_count"]
        unexplained = entry[f"unexplained_{row_type}_count"]
        expected = entry[f"expected_unpaired_{row_type}_count"]
        print(
            f"  {row_type} ({label}): raw original {original}, paired {paired}, "
            f"alias {aliases}, duplicate {duplicates}, unexplained {unexplained}, "
            f"expected-unpaired {expected}"
        )
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
        regression_errors = False
        if args.fail_on_regression:
            if func_baseline is None:
                raise FileNotFoundError(func_baseline_file)
            regressed, unpaired_now, _improved, _newly_paired = function_changes(
                curr_funcs, func_baseline
            )
            regression_errors = bool(regressed or unpaired_now)
            provenance_error = baseline_provenance_error(
                entry, baseline, tracked_worktree_is_clean(repo_root)
            )
            if provenance_error:
                print(f"Baseline provenance failed: {provenance_error}")
                regression_errors = True

        ui_errors: list[str] = []
        if args.ui_codegen_gate:
            if func_baseline is None:
                raise FileNotFoundError(func_baseline_file)
            from tools.ui_codegen import load_recipes

            recipes = load_recipes(repo_root)
            ui_errors = ui_codegen_regressions(
                (recipe.address for recipe in recipes), curr_funcs, func_baseline
            )
            print("")
            if ui_errors:
                print("Generated UI matching gate failed:")
                for error in ui_errors:
                    print(f"  - {error}")
            else:
                print(
                    f"Generated UI matching gate passed: {len(recipes)} paired, "
                    "no regressions"
                )

        if args.commit_baseline:
            if func_baseline is not None:
                regressed, unpaired_now, _improved, _newly_paired = function_changes(
                    curr_funcs, func_baseline
                )
                if unpaired_now:
                    raise RuntimeError(
                        "refusing baseline update with previously paired functions now unpaired: "
                        + ", ".join(address for address, _name, _score in unpaired_now)
                    )
            stub_ratchet_notice = clamp_stub_count_ratchet(entry, baseline)
            write_json_atomic(baseline_file, entry)
            write_function_baseline_atomic(func_baseline_file, curr_funcs)
            print("")
            print(f"Committed stats baseline: {baseline_file}")
            print(f"Committed function baseline: {func_baseline_file}")
            if stub_ratchet_notice:
                print(stub_ratchet_notice)
        return 1 if ui_errors or regression_errors else 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
