#!/usr/bin/env python3
"""Reject pairing or similarity regressions in resource-generated UI factories."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common.function_baseline import load_function_baseline
from tools.common.reccmp_report import run_report
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.report_score import effective_matching
from tools.ui_codegen import load_recipes


EPSILON = 1e-4
DEFAULT_BASELINE = "config/baselines/reccmp_progress_baseline.functions.csv"


def _scores(rows: list[dict]) -> dict[int, float]:
    scores: dict[int, float] = {}
    for row in rows:
        address = row.get("address")
        if address:
            scores[int(str(address), 16)] = effective_matching(row)
    return scores


def _baseline_scores(path: Path) -> dict[int, float]:
    functions = load_function_baseline(path)
    if functions is None:
        raise FileNotFoundError(path)
    return {
        int(address, 16): float(function["m"])
        for address, function in functions.items()
    }


def check_scores(
    addresses: list[int], current: dict[int, float], baseline: dict[int, float]
) -> list[str]:
    errors: list[str] = []
    for address in addresses:
        if address not in baseline:
            errors.append(f"0x{address:08x}: missing from committed baseline")
            continue
        if address not in current:
            errors.append(f"0x{address:08x}: generated function is not paired")
            continue
        before = baseline[address]
        after = current[address]
        if after < before - EPSILON:
            errors.append(
                f"0x{address:08x}: similarity regressed "
                f"{before * 100:.4f}% -> {after * 100:.4f}%"
            )
    return errors


def main() -> int:
    repo_root = repo_root_from_file(__file__, levels_up=2)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default="build-msvc500")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    args = parser.parse_args()

    build_dir = resolve_repo_path(repo_root, args.build_dir)
    baseline_path = resolve_repo_path(repo_root, args.baseline)
    addresses = [recipe.address for recipe in load_recipes(repo_root)]
    current_rows = run_report(args.target, build_dir, diet=True)
    current = _scores(current_rows)
    baseline = _baseline_scores(baseline_path)
    errors = check_scores(addresses, current, baseline)

    for address in addresses:
        current_score = current.get(address)
        baseline_score = baseline.get(address)
        current_text = "missing" if current_score is None else f"{current_score * 100:.4f}%"
        baseline_text = (
            "missing" if baseline_score is None else f"{baseline_score * 100:.4f}%"
        )
        print(f"0x{address:08x}: {current_text} (baseline {baseline_text})")

    if errors:
        print("UI codegen matching gate failed:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"UI codegen matching gate passed: {len(addresses)} paired, no regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
