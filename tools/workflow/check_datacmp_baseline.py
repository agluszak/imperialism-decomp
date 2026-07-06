#!/usr/bin/env python3
"""Gate global-data drift: reccmp-datacmp results vs a checked-in baseline.

`reccmp-datacmp` reports per-variable value differences between the original
and recompiled binaries but always exits 0, so data regressions only surface
when someone reads the output. This wraps it in the standard ratchet: parse
the report into per-variable fingerprints (status + number of differing-byte
detail lines) and compare against config/datacmp_baseline.csv:

  - a variable not in the baseline           -> FAIL (new data mismatch)
  - status worsened or diff-line count grew  -> FAIL (regressed global)
  - fewer diffs / fewer variables            -> PASS + ratchet reminder

`--write-baseline` records the current fingerprints. Needs a built binary
(reccmp detect) like the other comparison targets.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

ENTRY_RE = re.compile(r"^(?P<name>\S.*?) \((?P<addr>0x[0-9a-fA-F]+)\) \.\.\. (?P<status>[A-Z]+)")
DETAIL_RE = re.compile(r"^\s+\+ 0x[0-9a-fA-F]+\s")
STATUS_RANK = {"OK": 0, "WARN": 1, "ERROR": 2, "FAIL": 2}


def parse_report(text: str) -> dict[str, dict[str, str]]:
    """name -> {address, status, diffs} from reccmp-datacmp --no-color output."""
    entries: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        m = ENTRY_RE.match(line)
        if m:
            current = {
                "name": m.group("name"),
                "address": m.group("addr").lower(),
                "status": m.group("status"),
                "diffs": "0",
            }
            entries[current["name"]] = current
            continue
        if current is not None and DETAIL_RE.match(line):
            current["diffs"] = str(int(current["diffs"]) + 1)
    return entries


def compare(
    current: dict[str, dict[str, str]], baseline: dict[str, dict[str, str]]
) -> tuple[list[str], int]:
    """(violations, improvement_count) of current vs baseline fingerprints."""
    violations: list[str] = []
    improved = 0
    for name, row in sorted(current.items()):
        base = baseline.get(name)
        if base is None:
            violations.append(
                f"{name} ({row['address']}): new {row['status']} with {row['diffs']} "
                "differing bytes (not in baseline)"
            )
            continue
        rank_now = STATUS_RANK.get(row["status"], 2)
        rank_base = STATUS_RANK.get(base["status"], 2)
        if rank_now > rank_base:
            violations.append(
                f"{name} ({row['address']}): status {base['status']} -> {row['status']}"
            )
        elif int(row["diffs"]) > int(base["diffs"]):
            violations.append(
                f"{name} ({row['address']}): differing bytes {base['diffs']} -> {row['diffs']}"
            )
        elif rank_now < rank_base or int(row["diffs"]) < int(base["diffs"]):
            improved += 1
    improved += sum(1 for name in baseline if name not in current)
    return violations, improved


def run_datacmp(target: str, build_dir: Path) -> str:
    proc = subprocess.run(
        ["uv", "run", "reccmp-datacmp", "--target", target, "--no-color"],
        cwd=build_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def write_baseline(path: Path, entries: dict[str, dict[str, str]]) -> None:
    lines = ["name|address|status|diffs"]
    for name in sorted(entries):
        row = entries[name]
        lines.append(f"{name}|{row['address']}|{row['status']}|{row['diffs']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    parser.add_argument(
        "--baseline", default=str(repo_root / "config" / "datacmp_baseline.csv")
    )
    parser.add_argument("--report-file", default="", help="Parse this saved output instead of running datacmp")
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    if args.report_file:
        text = Path(args.report_file).read_text(encoding="utf-8", errors="replace")
    else:
        text = run_datacmp(args.target, resolve_repo_path(repo_root, args.build_dir))
    current = parse_report(text)
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    if args.write_baseline:
        write_baseline(baseline_path, current)
        print(f"Wrote baseline: {baseline_path} ({len(current)} variables)")
        return 0

    if not baseline_path.exists():
        print(f"Baseline missing: {baseline_path}")
        print("Run `just datacmp-gate-update` once, then re-run the gate.")
        return 1

    baseline = {row["name"]: row for row in read_pipe_rows(baseline_path)}
    violations, improved = compare(current, baseline)
    if violations:
        print(f"Datacmp gate FAILED ({len(violations)} regressed globals):")
        for item in violations[:40]:
            print(f"  - {item}")
        if len(violations) > 40:
            print(f"  ... {len(violations) - 40} more")
        print("Inspect with `just datacmp`; a wrong value/placement in "
              "global_data_tables.cpp is the usual cause.")
        return 1

    tail = f"; {improved} improved — run `just datacmp-gate-update` to ratchet" if improved else ""
    print(f"Datacmp gate passed: {len(current)} mismatching variables (== baseline){tail}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
