#!/usr/bin/env python3
"""Gate the autogen stub count against a checked-in baseline (ratchet down).

A RISING stub count after `just regen-stubs` is the tell for the
sync-ownership prune trap: marker-less-but-real ownership rows (DYNCREATE
GetRuntimeClass bodies, scalar deleting destructors, name-paired methods) got
pruned and re-stubbed, which silently breaks vtables. Restore such rows with
note=name_paired_no_marker instead of committing the regression.

Reads stub_count from src/autogen/stubs/_manifest.json (written by stubgen):
  - count > baseline  -> FAIL (new stubs appeared; find what got re-stubbed)
  - count < baseline  -> PASS + reminder to ratchet the baseline down
  - count == baseline -> PASS

`--write-baseline` records the current count (config/stub_count_baseline.json).
"""

from __future__ import annotations

import argparse
import json

from tools.common.repo import repo_root_from_file, resolve_repo_path


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=str(repo_root / "src" / "autogen" / "stubs" / "_manifest.json"),
    )
    parser.add_argument(
        "--baseline",
        default=str(repo_root / "config" / "stub_count_baseline.json"),
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Record the current stub count as the baseline and exit.",
    )
    return parser.parse_args()


def compare_counts(current: int, baseline: int) -> tuple[int, str]:
    """(exit_code, message) for a current count vs the baseline."""
    if current > baseline:
        return 1, (
            f"Stub-count gate FAILED: {baseline} -> {current} (+{current - baseline}).\n"
            "New autogen stubs appeared. If you didn't add symbols.csv rows on purpose,\n"
            "this is the sync-ownership prune trap: real marker-less owners (DYNCREATE\n"
            "GetRuntimeClass, scalar deleting dtors) were pruned and re-stubbed.\n"
            "Diff config/function_ownership.csv and restore pruned rows with\n"
            "note=name_paired_no_marker; do not commit around this failure."
        )
    if current < baseline:
        return 0, (
            f"Stub-count gate passed: {current} (baseline {baseline}; "
            f"-{baseline - current} — run `just stub-count-gate-update` to ratchet down)."
        )
    return 0, f"Stub-count gate passed: {current} stubs (== baseline)."


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    manifest_path = resolve_repo_path(repo_root, args.manifest)
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    current = int(json.loads(manifest_path.read_text())["stub_count"])

    if args.write_baseline:
        baseline_path.write_text(json.dumps({"stub_count": current}, indent=2) + "\n")
        print(f"Wrote baseline: {baseline_path} (stub_count={current})")
        return 0

    if not baseline_path.exists():
        print(f"Baseline missing: {baseline_path}")
        print("Run `just stub-count-gate-update` once, then re-run the gate.")
        return 1

    baseline = int(json.loads(baseline_path.read_text())["stub_count"])
    code, message = compare_counts(current, baseline)
    print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
