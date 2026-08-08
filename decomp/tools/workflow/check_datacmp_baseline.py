#!/usr/bin/env python3
"""Gate global-data drift: reccmp-datacmp results vs a checked-in baseline.

`reccmp-datacmp` reports per-variable value differences between the original
and recompiled binaries and exits 1 when it finds an issue. This wraps it in
the standard ratchet: preserve valid mismatch output from exit 1, parse
the report into per-variable fingerprints (status + number of differing-byte
detail lines + an optional normalization note) and compare against
config/baselines/datacmp_baseline.csv:

  - a variable not in the baseline           -> FAIL (new data mismatch)
  - status worsened or diff-line count grew  -> FAIL (regressed global)
  - fewer diffs / fewer variables            -> PASS + ratchet reminder

Pointer-only records are excluded up front: MFC CRuntimeClass descriptors
(`Foo::classFoo`) and `g_apfn...` function-pointer tables. Their byte diffs are
linked-address relocation noise that jitters whenever unrelated code moves.

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
STATUS_RANK = {"OK": 0, "WARN": 1, "DIFF": 2, "ERROR": 2, "FAIL": 2}

# A compiler may place a source-level zero initializer in BSS while the original
# linker kept the same zero bytes in initialized data. Both images expose the same
# runtime value after loading; reccmp-datacmp reports only the section-placement
# distinction as "0.0 : (uninitialized)".
ZERO_VS_BSS_DETAIL_RE = re.compile(
    r"^\s+\+ 0x[0-9a-fA-F]+\s+0(?:\.0*)?\s+:\s+\(uninitialized\)\s*$"
)

# MFC runtime-class records and function-pointer tables are composed primarily or
# entirely of linked addresses. Those addresses cannot match until the referenced
# code does, and unrelated code-size changes make their raw byte-diff counts jitter.
# Keep scalar and value-table globals guarded while excluding this relocation noise.
RELOCATION_ONLY_RE = re.compile(r"(?:::class[A-Za-z0-9_]+$|^g_apfn[A-Za-z0-9_]*$)")


def parse_report(text: str) -> dict[str, dict[str, str]]:
    """name -> {address, status, diffs, note} from a datacmp report.

    Pointer-only records (see RELOCATION_ONLY_RE) are skipped as relocation noise.
    A DIFF made solely of initialized-zero vs BSS-zero details is normalized to a
    WARN because the loader produces the same runtime value.
    """
    entries: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        m = ENTRY_RE.match(line)
        if m:
            name = m.group("name")
            if RELOCATION_ONLY_RE.search(name):
                current = None  # drop this entry and its detail lines
                continue
            current = {
                "name": name,
                "address": m.group("addr").lower(),
                "status": m.group("status"),
                "diffs": "0",
                "note": "",
                "_zero_vs_bss_only": "1",
            }
            entries[name] = current
            continue
        if current is not None and DETAIL_RE.match(line):
            current["diffs"] = str(int(current["diffs"]) + 1)
            if not ZERO_VS_BSS_DETAIL_RE.match(line):
                current["_zero_vs_bss_only"] = "0"

    for row in entries.values():
        if (
            row["status"] == "DIFF"
            and row["diffs"] != "0"
            and row.pop("_zero_vs_bss_only") == "1"
        ):
            row["status"] = "WARN"
            row["note"] = "initialized_zero_vs_bss_zero_same_runtime_value"
        else:
            row.pop("_zero_vs_bss_only", None)
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
        check=False,
    )
    # reccmp-datacmp uses 1 for a completed comparison with mismatches.  That
    # report is exactly what both the ratchet and --write-baseline must parse.
    # Reject status 1 when the normal summary is absent so actual invocation or
    # analysis failures cannot be mistaken for valid mismatch evidence.
    valid_mismatch_report = proc.returncode == 1 and re.search(
        r" - Variables: \d+\. Issues: \d+\s*$", proc.stdout
    )
    if proc.returncode != 0 and not valid_mismatch_report:
        raise subprocess.CalledProcessError(
            proc.returncode,
            proc.args,
            output=proc.stdout,
            stderr=proc.stderr,
        )
    return proc.stdout


def write_baseline(path: Path, entries: dict[str, dict[str, str]]) -> None:
    lines = ["name|address|status|diffs|note"]
    for name in sorted(entries):
        row = entries[name]
        lines.append(
            f"{name}|{row['address']}|{row['status']}|{row['diffs']}|{row.get('note', '')}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    parser.add_argument(
        "--baseline", default=str(repo_root / "config" / "baselines" / "datacmp_baseline.csv")
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
