#!/usr/bin/env python3
"""Enforce mechanically provable CString source-model invariants.

Imperialism uses the real VC5/MFC CString.  Manual game source must not replace it
with a one-pointer lookalike or reach into CString/CStringData internals.  Mutable
buffer access must be closed with ReleaseBuffer, and CString objects passed through
the retail stack-indexed string expander's ellipsis must be converted to LPCSTR
explicitly so VC5 pushes a character pointer rather than the four-byte object.

This is a baseline-free hard gate.  It intentionally does not guess whether an
arbitrary raw byte span crosses a CString field or whether an inherited ShallowClone
path repairs every owned string; those require a generated layout/reachability audit.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.file_scan import iter_files, strip_generated_blocks
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

DEFAULT_PATHS = ("include/game", "src/game")

PROHIBITED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ATL CString header", re.compile(r"#\s*include\s*[<\"]atlstr\.h[>\"]")),
    ("ATL CString type", re.compile(r"\b(?:CStringT|CAtlString\w*)\b")),
    ("pseudo-CString type", re.compile(r"\bGhStr\b")),
    ("CString buffer internals", re.compile(r"(?:\.|->)\s*m_pchData\b")),
    ("CStringData internals", re.compile(r"\bCStringData\b|(?:\.|->)\s*nRefs\b")),
)

BUFFER_ACQUIRE = re.compile(
    r"(?P<receiver>\b[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*"
    r"(?:->|\.)GetBuffer(?:SetLength)?\s*\("
)
BUFFER_RELEASE = re.compile(
    r"(?P<receiver>\b[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*"
    r"(?:->|\.)ReleaseBuffer\s*\("
)

# These functions inspect their trailing arguments by pointer-arithmetic over the
# caller's x86 argument slots.  Their fixed arguments end immediately before the
# first string ellipsis argument.
STACK_STRING_VARARGS = {
    "scanBracketExpressions": 3,
    "FilterStringByCharacterTypeFlag4AndAppend": 3,
}

CSTRING_DECL = re.compile(
    r"\b(?:const\s+)?CString\s*(?:const\s*)?(?:[&*]\s*)?(?P<name>[A-Za-z_]\w*)"
)
EXPLICIT_CHAR_POINTER = re.compile(
    r"(?:static_cast\s*<\s*(?:LPCSTR|(?:const\s+)?char\s*\*)\s*>|"
    r"\(\s*(?:LPCSTR|(?:const\s+)?char\s*\*)\s*\))"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    kind: str
    detail: str


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def strip_comments(text: str) -> str:
    """Remove C/C++ comments while preserving offsets and line numbers."""
    pattern = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
    return pattern.sub(_blank, strip_generated_blocks(text))


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_closing_paren(text: str, open_offset: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for offset in range(open_offset, len(text)):
        char = text[offset]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return offset
    return None


def split_call_arguments(argument_text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    quote: str | None = None
    escaped = False
    for offset, char in enumerate(argument_text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char in depths:
            depths[char] += 1
        elif char in pairs and depths[pairs[char]] > 0:
            depths[pairs[char]] -= 1
        elif char == "," and not any(depths.values()):
            args.append(argument_text[start:offset].strip())
            start = offset + 1
    tail = argument_text[start:].strip()
    if tail or args:
        args.append(tail)
    return args


def iter_named_calls(text: str, function_name: str):
    call_start = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for match in call_start.finditer(text):
        open_offset = text.find("(", match.start(), match.end())
        close_offset = _find_closing_paren(text, open_offset)
        if close_offset is None:
            continue
        yield match.start(), split_call_arguments(text[open_offset + 1 : close_offset])


def collect_cstring_names(text: str) -> set[str]:
    return {match.group("name") for match in CSTRING_DECL.finditer(text)}


def is_cstring_expression(argument: str, cstring_names: set[str]) -> bool:
    if ".GetBuffer" in argument or "->GetBuffer" in argument:
        return True
    if re.search(r"\bCString\s*\(", argument):
        return True
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", argument))
    return bool(identifiers & cstring_names)


def collect_findings(paths, repo_root: Path) -> set[Finding]:
    findings: set[Finding] = set()
    source_units: list[tuple[Path, str, str]] = []
    all_cstring_names: set[str] = set()
    for path in iter_files(paths):
        rel = normalize_repo_relative_path(path, repo_root)
        source = path.read_text(encoding="utf-8", errors="ignore")
        text = strip_comments(source)
        source_units.append((path, rel, text))
        all_cstring_names.update(collect_cstring_names(text))

    for _path, rel, text in source_units:
        for label, pattern in PROHIBITED_PATTERNS:
            for match in pattern.finditer(text):
                findings.add(
                    Finding(rel, line_number(text, match.start()), "internal-model", label)
                )

        acquisitions: dict[str, list[int]] = {}
        releases: dict[str, list[int]] = {}
        for match in BUFFER_ACQUIRE.finditer(text):
            acquisitions.setdefault(match.group("receiver"), []).append(
                line_number(text, match.start())
            )
        for match in BUFFER_RELEASE.finditer(text):
            releases.setdefault(match.group("receiver"), []).append(
                line_number(text, match.start())
            )
        for receiver, acquire_lines in acquisitions.items():
            release_count = len(releases.get(receiver, []))
            if release_count < len(acquire_lines):
                findings.add(
                    Finding(
                        rel,
                        acquire_lines[release_count],
                        "buffer-lifetime",
                        f"{receiver}: {len(acquire_lines)} acquisition(s), "
                        f"{release_count} ReleaseBuffer call(s)",
                    )
                )

        for function_name, fixed_count in STACK_STRING_VARARGS.items():
            for offset, args in iter_named_calls(text, function_name):
                for argument in args[fixed_count:]:
                    if is_cstring_expression(argument, all_cstring_names) and not (
                        EXPLICIT_CHAR_POINTER.search(argument)
                    ):
                        findings.add(
                            Finding(
                                rel,
                                line_number(text, offset),
                                "varargs-object",
                                f"{function_name}: explicitly cast CString argument "
                                f"`{argument}` to LPCSTR",
                            )
                        )
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    findings = sorted(collect_findings(args.paths, repo_root))
    if findings:
        print("CString gate FAILED:")
        for finding in findings:
            print(
                f"  - {finding.path}:{finding.line}: "
                f"{finding.kind}: {finding.detail}"
            )
        print("Use real VC5 CString objects, pair mutable buffers with ReleaseBuffer, and")
        print("convert CString ellipsis arguments explicitly to LPCSTR.")
        return 1
    print("CString gate passed: real model, paired buffers, and safe string varargs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
