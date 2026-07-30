#!/usr/bin/env python3
"""Ratchet the control-tree mechanics still present in native runtime scenario bodies.

The linear-script authoring API exists so a scenario says what it does rather than how the
control tree is walked. A migrated scenario touches none of these:

    g_ModalViewStack   currentTurnEventCode   CurrentMainView   ResolveControlByTag
    RUNTIME_CLASS      RuntimeUiDriver        Await/AwaitUiChange
    ContinueAfterAction                       EnterScenarioStep
    AdvanceScenario    enum Phase

All of them are legitimate *below* the boundary -- in `screens/`, `flows/`, `probes/` and the
scenario base -- and none of them belong in a `*Test.cpp`. The point is the boundary, not the
identifiers.

This is a ratchet rather than a ban because migration is incremental: the baseline records how
many such references each unmigrated scenario still has. A count that falls rewrites the
baseline automatically, because tightening a ratchet is always safe. A count that rises, or a
new scenario with any references at all, fails -- so the old shape cannot come back and
half-migrating a file cannot be mistaken for progress.

A handful of references are not migration debt at all: pixel probes and renderer observation
hooks legitimately reach for the view tree. Those go in ALLOWLIST with a reason, not into the
baseline.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from tools.common.repo import repo_root_from_file


BASELINE_PATH = Path("config/baselines/runtime_script_debt.json")
SCENARIO_DIR = Path("tests/runtime/native/scenarios")

# Everything a migrated scenario should express through a screen, a flow or an RT_ macro.
MECHANICS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("modal stack", re.compile(r"\bg_ModalViewStack\b")),
    ("turn-event code", re.compile(r"\bcurrentTurnEventCode\b")),
    ("main view lookup", re.compile(r"\bCurrentMainView\s*\(")),
    ("tag resolution", re.compile(r"\bResolveControlByTag\s*\(")),
    ("runtime class", re.compile(r"\bRUNTIME_CLASS\s*\(")),
    ("ui driver", re.compile(r"\bRuntimeUiDriver::")),
    ("raw await", re.compile(r"\b(?:AwaitUiChange|Await)\s*\(")),
    ("raw continue", re.compile(r"\bContinueAfterAction\s*\(")),
    ("raw phase entry", re.compile(r"\bEnterScenarioStep\s*\(")),
    ("phase dispatcher", re.compile(r"\bAdvanceScenario\s*\(")),
    ("phase enum", re.compile(r"\benum\s+Phase\b")),
)

# Files exempt from the ratchet entirely, with the reason. Not migration debt: these reach for
# the view tree to do something the screen layer cannot express.
ALLOWLIST: dict[str, str] = {}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    source: str


def scenario_files(repo: Path) -> list[Path]:
    return sorted((repo / SCENARIO_DIR).glob("*Test.cpp"))


def scan_file(path: Path, repo: Path) -> list[Finding]:
    relative = path.relative_to(repo).as_posix()
    findings: list[Finding] = []
    for number, source in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = source.strip()
        # A comment that names a mechanic is documentation, not a use of it.
        if stripped.startswith("//"):
            continue
        for rule, pattern in MECHANICS:
            if pattern.search(source):
                findings.append(Finding(relative, number, rule, stripped))
    return findings


def counts_by_file(repo: Path) -> tuple[dict[str, int], dict[str, list[Finding]]]:
    counts: dict[str, int] = {}
    detail: dict[str, list[Finding]] = {}
    for path in scenario_files(repo):
        relative = path.relative_to(repo).as_posix()
        if relative in ALLOWLIST:
            continue
        findings = scan_file(path, repo)
        if findings:
            counts[relative] = len(findings)
            detail[relative] = findings
    return counts, detail


def load_baseline(repo: Path) -> dict[str, int]:
    path = repo / BASELINE_PATH
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    debt = data.get("debt", {})
    return {str(key): int(value) for key, value in debt.items()}


def write_baseline(repo: Path, counts: dict[str, int]) -> None:
    path = repo / BASELINE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "comment": (
            "Control-tree mechanics still present in unmigrated runtime scenario bodies. "
            "A ratchet: counts fall freely (the gate rewrites this file), a rise or a new "
            "entry fails. Zero entries means every scenario is a linear script and the "
            "ratchet can become a hard ban."
        ),
        "debt": dict(sorted(counts.items())),
        "total": sum(counts.values()),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Rewrite the baseline from the current tree, including rises (needs approval).",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="List every remaining reference rather than only the per-file counts.",
    )
    args = parser.parse_args(argv)

    repo = repo_root_from_file(__file__)
    counts, detail = counts_by_file(repo)
    baseline = load_baseline(repo)

    if args.write_baseline:
        write_baseline(repo, counts)
        print(f"wrote {BASELINE_PATH} ({sum(counts.values())} references in {len(counts)} files)")
        return 0

    if args.show:
        for path in sorted(detail):
            print(f"{path}:")
            for finding in detail[path]:
                print(f"  {finding.line}: {finding.rule}: {finding.source}")

    regressions: list[str] = []
    for path in sorted(counts):
        allowed = baseline.get(path)
        if allowed is None:
            regressions.append(
                f"{path}: {counts[path]} control-tree reference(s) in a scenario that had none. "
                f"Express these through a screen, a flow or an RT_ macro."
            )
        elif counts[path] > allowed:
            regressions.append(
                f"{path}: {counts[path]} control-tree reference(s), baseline {allowed}. "
                f"Migration debt must fall, never rise."
            )

    improvements = {
        path: (baseline[path], counts.get(path, 0))
        for path in baseline
        if counts.get(path, 0) < baseline[path]
    }

    if regressions:
        for line in regressions:
            print(f"runtime script debt: {line}")
        print(
            f"runtime script debt gate failed with {len(regressions)} regression(s); "
            f"run with --show to list the references"
        )
        return 1

    if improvements:
        # Tightening is always safe, so record it instead of asking for a second command.
        write_baseline(repo, counts)
        for path, (was, now) in sorted(improvements.items()):
            print(f"runtime script debt: {path} {was} -> {now}")
        print(f"tightened {BASELINE_PATH}; commit it with the source change")

    total = sum(counts.values())
    if total == 0:
        print("runtime script debt gate passed: every scenario is a linear script")
    else:
        print(
            f"runtime script debt gate passed: {total} reference(s) remaining in "
            f"{len(counts)} unmigrated scenario(s)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
