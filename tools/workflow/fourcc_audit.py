#!/usr/bin/env python3
"""Inventory and validate four-character identifiers in manually owned source.

Every tag constant must be spelled through IMPERIALISM_FOURCC so its numeric value and
its four characters cannot disagree. This audit classifies each tag by domain, rejects
raw hexadecimal or implementation-defined multi-character-literal spellings, rejects
duplicate values under competing names, and cross-checks the tags against the Mac
control-tag index.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path
from tools.common.repo import repo_root_from_file


REPORT_PATH = "docs/reference/fourcc-tag-audit.md"
MAC_INDEX_PATH = "docs/reference/mac_control_usage.json"
POLICY_HEADER = "include/game/ui_fourcc.h"

# Catalog headers, in domain order. A tag's domain is the catalog that declares it.
CATALOGS = {
    "include/game/ui_tags_common.h": "ui_tag_shared",
    "include/game/ui_tags_screens.h": "ui_tag_app_and_setup_screens",
    "include/game/ui_tags_map.h": "ui_tag_strategic_map",
    "include/game/ui_tags_city.h": "ui_tag_city_and_trade",
    "include/game/ui_tags_diplomacy.h": "ui_tag_diplomacy",
    "include/game/ui_tags_military.h": "ui_tag_military_navy_tactical",
    "include/game/ui_tags_widgets.h": "ui_tag_widget_plumbing",
    "include/game/multiplayer_session_tags.h": "multiplayer_session_or_message_tag",
    "include/game/resource_manifest_tags.h": "generated_resource_manifest_tag",
}

_MACRO_DECL_RE = re.compile(
    r"const int (?P<name>\w+)\s*=\s*IMPERIALISM_FOURCC\(\s*"
    r"'(?P<a>[^']|\\.)'\s*,\s*'(?P<b>[^']|\\.)'\s*,\s*'(?P<c>[^']|\\.)'\s*,\s*'(?P<d>[^']|\\.)'\s*\)\s*;"
)
# A 32-bit hex literal whose four bytes are all printable ASCII is a FourCC spelled the
# old way; the trailing comment usually renders the characters.
_RAW_HEX_RE = re.compile(r"\b0x(?P<value>[0-9a-fA-F]{8})u?\b")
# Implementation-defined multi-character literal, e.g. 'text'. The character class
# excludes quotes, backslashes, and commas so neither escape sequences nor a
# comma-separated list of single-character literals is mistaken for one.
_MULTICHAR_RE = re.compile(r"(?<![\w'\\])'[^'\\,\n]{2,4}'(?!')")


@dataclass(frozen=True)
class Tag:
    name: str
    value: int
    characters: str
    catalog: str
    domain: str


@dataclass(frozen=True)
class Violation:
    kind: str
    location: str
    detail: str


def _printable_fourcc(value: int) -> str | None:
    characters = "".join(chr((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    if all(0x20 <= ord(character) <= 0x7E for character in characters):
        return characters
    return None


def _manual_sources(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for base in (repo_root / "include" / "game", repo_root / "src" / "game"):
        for path in base.rglob("*"):
            if path.suffix not in (".h", ".cpp"):
                continue
            if is_excluded_scan_path(path, roots=[repo_root]):
                continue
            paths.append(path)
    return sorted(paths)


def collect(repo_root: Path) -> tuple[list[Tag], list[Violation]]:
    tags: list[Tag] = []
    violations: list[Violation] = []

    for catalog, domain in CATALOGS.items():
        path = repo_root / catalog
        if not path.exists():
            continue
        for match in _MACRO_DECL_RE.finditer(path.read_text(encoding="utf-8")):
            characters = "".join(match.group(key) for key in ("a", "b", "c", "d"))
            value = 0
            for character in characters:
                value = (value << 8) | ord(character)
            tags.append(Tag(match.group("name"), value, characters, catalog, domain))

    by_value: dict[int, list[str]] = defaultdict(list)
    by_name: dict[str, list[str]] = defaultdict(list)
    for tag in tags:
        by_value[tag.value].append(tag.name)
        by_name[tag.name].append(tag.catalog)
    for value, names in sorted(by_value.items()):
        if len(names) > 1:
            violations.append(
                Violation(
                    "duplicate_tag_value",
                    "/".join(sorted(CATALOGS)),
                    f"0x{value:08x} ({_printable_fourcc(value)!r}) declared as {', '.join(sorted(names))}",
                )
            )
    for name, catalogs in sorted(by_name.items()):
        if len(catalogs) > 1:
            violations.append(
                Violation("duplicate_tag_name", ", ".join(catalogs), name)
            )

    known_values = {tag.value for tag in tags}
    for path in _manual_sources(repo_root):
        relative = path.relative_to(repo_root).as_posix()
        if relative == POLICY_HEADER:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        # Blank out block comments while preserving line numbering.
        text = re.sub(
            r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S
        )
        for line_number, source in enumerate(text.splitlines(), 1):
            code = source.split("//", 1)[0]
            if "IMPERIALISM_FOURCC" in code:
                continue
            for match in _RAW_HEX_RE.finditer(code):
                value = int(match.group("value"), 16)
                characters = _printable_fourcc(value)
                if characters is None or value not in known_values:
                    continue
                violations.append(
                    Violation(
                        "raw_hex_tag_spelling",
                        f"{relative}:{line_number}",
                        f"0x{value:08x} is the tag {characters!r}; use its catalog constant",
                    )
                )
            for match in _MULTICHAR_RE.finditer(code):
                violations.append(
                    Violation(
                        "multi_character_literal",
                        f"{relative}:{line_number}",
                        f"{match.group(0)} is implementation-defined; use IMPERIALISM_FOURCC",
                    )
                )

    return tags, violations


def _mac_index(repo_root: Path) -> dict[int, dict]:
    path = repo_root / MAC_INDEX_PATH
    if not path.exists():
        return {}
    index = json.loads(path.read_text(encoding="utf-8")).get("tags", {})
    return {row["tag_value"]: row for row in index.values() if "tag_value" in row}


def render_report(tags: list[Tag], violations: list[Violation], mac: dict[int, dict]) -> str:
    domains = Counter(tag.domain for tag in tags)
    corroborated = [tag for tag in tags if tag.value in mac]
    lines = [
        "<!-- AUTO-GENERATED by tools/workflow/fourcc_audit.py; DO NOT EDIT. -->",
        "# Four-character tag audit",
        "",
        "Every manually owned four-character identifier is declared through",
        f"`IMPERIALISM_FOURCC` in a domain catalog, so its numeric value and its four",
        "characters cannot disagree. See `include/game/ui_fourcc.h` for the encoding",
        "policy (Mac resource order, read big-endian).",
        "",
        "## Summary",
        "",
        f"- Tags: {len(tags)}",
    ]
    for domain in sorted(domains):
        lines.append(f"- `{domain}`: {domains[domain]}")
    lines.extend(
        (
            f"- Corroborated by the Mac control-tag index: {len(corroborated)}"
            f" of {len(tags)}",
            f"- Violations: {len(violations)}",
            "",
            "## Violations",
            "",
        )
    )
    if violations:
        lines.extend(("| Kind | Location | Detail |", "| --- | --- | --- |"))
        for violation in violations:
            lines.append(
                f"| `{violation.kind}` | `{violation.location}` | {violation.detail} |"
            )
    else:
        lines.append("None.")
    lines.extend(
        (
            "",
            "## Tags",
            "",
            "`Mac screens` counts the Mac resource screens that instantiate a control with",
            "this tag. A blank cell means the tag is Windows-only or generated, which is",
            "expected for sequential families and for setup/multiplayer screens the Mac",
            "build does not ship.",
            "",
            "| Name | Characters | Value | Domain | Mac screens |",
            "| --- | --- | --- | --- | --- |",
        )
    )
    for tag in sorted(tags, key=lambda row: (row.domain, row.name)):
        row = mac.get(tag.value)
        screens = str(row["screen_count"]) if row else ""
        lines.append(
            f"| `{tag.name}` | `{tag.characters}` | `0x{tag.value:08x}` | "
            f"`{tag.domain}` | {screens} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="rewrite the report")
    action.add_argument("--check", action="store_true", help="fail on violations or report drift")
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=2)

    tags, violations = collect(repo_root)
    report = render_report(tags, violations, _mac_index(repo_root))
    report_path = repo_root / REPORT_PATH

    if args.write:
        report_path.write_text(report, encoding="utf-8")
        print(f"Wrote FourCC tag audit: {len(tags)} tags, {len(violations)} violation(s)")
        return 0

    if args.check:
        if violations:
            print(f"FourCC tag audit failed: {len(violations)} violation(s)")
            for violation in violations[:20]:
                print(f"  {violation.kind}: {violation.location}: {violation.detail}")
            return 1
        if not report_path.exists() or report_path.read_text(encoding="utf-8") != report:
            print(f"FourCC tag audit failed: {REPORT_PATH} is stale; run with --write")
            return 1
        print(f"FourCC tag audit passed: {len(tags)} tags, no violations")
        return 0

    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
