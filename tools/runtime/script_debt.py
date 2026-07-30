#!/usr/bin/env python3
"""Ban control-tree mechanics from native runtime scenario bodies.

The linear-script authoring API exists so a scenario says what it does rather than how the
control tree is walked. A scenario touches none of these:

    g_ModalViewStack   currentTurnEventCode   CurrentMainView   ResolveControlByTag
    RUNTIME_CLASS      RuntimeUiDriver        Await/AwaitUiChange
    ContinueAfterAction                       EnterScenarioStep
    AdvanceScenario    enum Phase

All of them are legitimate *below* the boundary -- in `screens/`, `flows/`, `probes/` and the
scenario base -- and none of them belong in a `*Test.cpp`. The point is the boundary, not the
identifiers.

This was a ratchet while the suite was being migrated: a per-file baseline of how many such
references each unmigrated scenario still had, which could fall but never rise. Every scenario is
now a linear script, so the baseline is gone and this is a hard ban -- there is no count to bless
and no `--write-baseline` to reach for. A new reference is a scenario reaching through the
boundary instead of extending it: put the mechanic in a screen, a flow or a probe and let the
scenario ask for what it means.

A reference that genuinely cannot live below the boundary goes in ALLOWLIST with a reason. It is
empty, and the bar for adding to it is that no screen, flow or probe could own the thing -- not
that writing one would be work.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from tools.common.repo import repo_root_from_file


SCENARIO_DIR = Path("tests/runtime/native/scenarios")

# Everything a scenario should express through a screen, a flow or an RT_ macro.
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

# Files exempt from the ban, with the reason. Empty, and meant to stay that way.
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


def findings_by_file(repo: Path) -> dict[str, list[Finding]]:
    detail: dict[str, list[Finding]] = {}
    for path in scenario_files(repo):
        relative = path.relative_to(repo).as_posix()
        if relative in ALLOWLIST:
            continue
        findings = scan_file(path, repo)
        if findings:
            detail[relative] = findings
    return detail


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--show",
        action="store_true",
        help="List every reference found (they are all failures now).",
    )
    args = parser.parse_args(argv)

    repo = repo_root_from_file(__file__)
    detail = findings_by_file(repo)

    if not detail:
        print("runtime script debt gate passed: every scenario is a linear script")
        return 0

    for path in sorted(detail):
        findings = detail[path]
        print(
            f"runtime script debt: {path}: {len(findings)} control-tree reference(s) in a "
            f"scenario body. Express these through a screen, a flow or a probe."
        )
        if args.show:
            for finding in findings:
                print(f"  {finding.line}: {finding.rule}: {finding.source}")

    total = sum(len(findings) for findings in detail.values())
    print(
        f"runtime script debt gate failed: {total} control-tree reference(s) in "
        f"{len(detail)} scenario(s)"
        + ("" if args.show else "; run with --show to list them")
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
