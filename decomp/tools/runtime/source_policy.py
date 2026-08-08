"""Reject control-tree mechanics, coordinate input, and polling from native scenarios.

Scenario bodies (`tests/runtime/native/scenarios/*Test.cpp`) express intent through
screens, flows, probes, and RT_ macros. They must not reach into UI internals,
synthesize window messages, draw with GDI/QuickDraw, or poll time.

Domain-model headers stay available: assertions are the point of a scenario.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


# Boundary reaches that belong in screens/flows/probes, not scenario bodies.
SCENARIO_BOUNDARY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
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
    (
        "gdi surface",
        re.compile(
            r"\b(?:CreateDIBSection|CreateCompatibleDC|SelectObject|"
            r"DeleteDC|GdiFlush|PatBlt|BitBlt|DrawIconEx)\s*\("
        ),
    ),
    ("device context", re.compile(r"\b(?:GetDC|ReleaseDC|RedrawWindow)\s*\(")),
    (
        "quickdraw surface",
        re.compile(
            r"\b(?:GetGWorld|SetGWorld|GetGWorldPixMap|LockPixels|UnlockPixels)\s*\("
        ),
    ),
    ("synthesised input", re.compile(r"\b(?:SendMessageA?|PostMessageA?)\s*\(")),
    ("cursor state", re.compile(r"\b(?:SetCursor|GetCursor)\s*\(")),
)

# Timing / coordinate bans apply to the whole native runtime tree.
FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mouse button message", re.compile(r"\bWM_LBUTTON(?:DOWN|UP)\b")),
    ("test timer", re.compile(r"\bSetTimer\s*\(")),
    ("thread sleep", re.compile(r"\bSleep\s*\(")),
    ("scenario tick count", re.compile(r"\bScenarioPhaseTicks\s*\(")),
    ("scenario elapsed time", re.compile(r"\bScenarioPhaseElapsedMs\s*\(")),
    ("scenario tick polling", re.compile(r"\bWaitForScenarioTick\s*\(")),
    ("scenario tick request", re.compile(r"\bRequestScenarioTick\s*\(")),
    (
        "coordinate control activation",
        re.compile(
            r"\b(?:ClickView(?:Point)?ThroughNativeMessages|"
            r"ClickControlThroughNativeMessages|Queue\w*ClickThroughNativeMessages)\b"
        ),
    ),
)

LITERAL_POINT = re.compile(
    r"\bCPoint(?:\s+\w+)?\s*\(\s*-?(?:0x[0-9a-f]+|\d+)\s*,"
    r"\s*-?(?:0x[0-9a-f]+|\d+)\s*\)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str
    source: str


def _source_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(path.rglob("*.cpp"))
            yield from sorted(path.rglob("*.h"))
        elif path.suffix in {".cpp", ".h"}:
            yield path


def _is_scenario_body(path: Path) -> bool:
    parts = path.parts
    return "scenarios" in parts and path.name.endswith("Test.cpp")


def check_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in _source_files(paths):
        scenario = _is_scenario_body(path)
        for line_number, source in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = source.strip()
            if stripped.startswith("//"):
                continue
            patterns = FORBIDDEN_PATTERNS
            if scenario:
                patterns = SCENARIO_BOUNDARY_PATTERNS + FORBIDDEN_PATTERNS
            for rule, pattern in patterns:
                if pattern.search(source):
                    findings.append(Finding(path, line_number, rule, stripped))
            if (
                "RUNTIME_COORDINATE_EXPLAINED" not in source
                and LITERAL_POINT.search(source)
            ):
                findings.append(
                    Finding(path, line_number, "unexplained literal point", stripped)
                )
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[Path("tests/runtime/native")],
    )
    args = parser.parse_args(argv)
    findings = check_paths(args.paths)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.rule}: {finding.source}")
    if findings:
        print(f"runtime source policy failed with {len(findings)} finding(s)")
        return 1
    print("runtime source policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
