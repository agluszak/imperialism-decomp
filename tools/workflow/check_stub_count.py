#!/usr/bin/env python3
"""Gate the generated stub count against a checked-in baseline (ratchet down).

Stubs are build artifacts now — this gate computes the stub set the generator
would emit (tools.stubgen.compute_stub_rows: symbols.csv function-kind rows minus
source-claimed addresses) instead of reading committed files, so it needs no
build and can never disagree with generation.

A RISING stub count is the tell for accidental un-claiming: a real marker-less
owner (DYNCREATE GetRuntimeClass bodies, scalar deleting destructors, name-paired
methods) lost its claim and would be re-stubbed, which silently breaks vtables.

  - count > baseline  -> FAIL (new stubs appeared; find what got un-claimed)
  - count < baseline  -> PASS + reminder to ratchet the baseline down
  - count == baseline -> PASS

The baseline value is the `stub_count` field of config/baselines/reccmp_progress_baseline.json
(it used to live in a separate stub_count_baseline.json). `stats-baseline-update`
recomputes it as part of the full progress snapshot; `--write-baseline` here updates
just that one field in place (cheap, no build) for ratcheting down between snapshots.
"""

from __future__ import annotations

import argparse
import json

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.stubgen import compute_stub_rows


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        default=str(repo_root / "config" / "baselines" / "reccmp_progress_baseline.json"),
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
            "New stubs would be generated. If you didn't add symbols.csv rows on\n"
            "purpose, a real marker-less owner (DYNCREATE GetRuntimeClass, scalar\n"
            "deleting dtor, name-paired method) lost its claim and would be re-stubbed.\n"
            "Add the missing marker/claim; do not commit around this failure."
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
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    current = len(compute_stub_rows(repo_root))

    if args.write_baseline:
        # Read-modify-write only the stub_count field of the progress baseline so the
        # rest of the snapshot (produced by stats-baseline-update) is preserved.
        data = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}
        data["stub_count"] = current
        baseline_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"Updated stub_count in {baseline_path} (stub_count={current})")
        return 0

    if not baseline_path.exists():
        print(f"Baseline missing: {baseline_path}")
        print("Run `just stats-baseline-update` once, then re-run the gate.")
        return 1

    baseline_data = json.loads(baseline_path.read_text())
    if "stub_count" not in baseline_data:
        print(f"Baseline {baseline_path} has no `stub_count` field.")
        print("Run `just stats-baseline-update` (or `just stub-count-gate-update`) to record it.")
        return 1

    baseline = int(baseline_data["stub_count"])
    code, message = compare_counts(current, baseline)
    print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
