"""Reject coordinate input and polling synchronization in native runtime scenarios."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


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


def check_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in _source_files(paths):
        for line_number, source in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for rule, pattern in FORBIDDEN_PATTERNS:
                if pattern.search(source):
                    findings.append(Finding(path, line_number, rule, source.strip()))
            if (
                "RUNTIME_COORDINATE_EXPLAINED" not in source
                and LITERAL_POINT.search(source)
            ):
                findings.append(
                    Finding(path, line_number, "unexplained literal point", source.strip())
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
