#!/usr/bin/env python3
"""Report and ratchet high-signal scalar conversion and enum-candidate patterns."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from tools.common.file_scan import is_excluded_scan_path
from tools.common.repo import repo_root_from_file


FORMAT_VERSION = 1
CONFIG_PATH = "config/scalar_type_audit.yml"
BASELINE_PATH = "config/baselines/scalar_type_audit.json"
REPORT_PATH = "docs/reference/scalar-type-audit.md"

INTEGRAL_TYPES = (
    "bool",
    "char",
    "signed char",
    "unsigned char",
    "short",
    "unsigned short",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "BOOL",
    "BYTE",
    "WORD",
    "DWORD",
    "UINT",
    "WPARAM",
    "LPARAM",
    "LRESULT",
)
_TYPE_PATTERN = "|".join(re.escape(value) for value in sorted(INTEGRAL_TYPES, key=len, reverse=True))
_NESTED_CAST_RE = re.compile(
    rf"static_cast\s*<\s*(?P<outer>{_TYPE_PATTERN})\s*>\s*\(\s*"
    rf"static_cast\s*<\s*(?P<inner>{_TYPE_PATTERN})\s*>\s*\("
)
_PREDICATE_CAST_RE = re.compile(
    r"static_cast\s*<\s*(?P<type>bool|BOOL|char|signed char|unsigned char)\s*>\s*\("
)
_COMPARISON_RE = re.compile(r"==|!=|<=|>=|(?<![<=])<(?![<=])|(?<![-=>])>(?![=>])")
_DISCRIMINANT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*(?:Type|Kind|Mode|State|Code)\w*)\b\s*"
    r"(?P<operator>==|!=|<=|>=|<|>)\s*(?P<literal>0x[0-9a-fA-F]+|[0-9]+)\b"
)
_NATIVE_CAST_RE = re.compile(
    r"static_cast\s*<\s*(?P<type>BOOL|BYTE|WORD|DWORD|UINT|WPARAM|LPARAM|LRESULT)\s*>\s*\("
)


DISCRIMINANT_REVIEWS_KEY = "discriminant_reviews"
PREDICATE_REVIEWS_KEY = "predicate_storage_reviews"
BOOL_INVENTORY_PATH = "docs/reference/bool-boundary-inventory.csv"


@dataclass(frozen=True)
class Finding:
    category: str
    path: str
    line: int
    detail: str
    source: str
    classification: str
    owner: str
    occurrence: int

    @property
    def family(self) -> str:
        """The identifier a raw_discriminant_literal finding compares.

        Findings are reviewed per identifier family, not per site: one comparison of
        `resourceType` against a literal is the same modelling question as the next.
        """
        return self.detail.split(" ", 1)[0]

    @property
    def fingerprint(self) -> str:
        normalized = re.sub(r"\s+", " ", self.source.strip())
        payload = (
            f"{self.category}\0{self.path}\0{self.detail}\0{normalized}\0{self.occurrence}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _load_config(repo_root: Path) -> dict:
    config = yaml.safe_load((repo_root / CONFIG_PATH).read_text(encoding="utf-8"))
    if config.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"{CONFIG_PATH}: unsupported format_version")
    categories = config.get("categories", {})
    for category in (
        "nested_integral_cast",
        "predicate_storage_cast",
        "raw_discriminant_literal",
        "native_integral_boundary",
    ):
        row = categories.get(category, {})
        if not row.get("classification") or not row.get("owner") or not row.get("rationale"):
            raise ValueError(f"{CONFIG_PATH}: incomplete classification for {category}")
    return config


def _manual_paths(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for base in (repo_root / "include" / "game", repo_root / "src" / "game"):
        for path in base.rglob("*"):
            if path.suffix not in (".h", ".cpp"):
                continue
            if is_excluded_scan_path(path, roots=[repo_root]):
                continue
            paths.append(path)
    return sorted(paths)


def _balanced_argument(text: str, open_paren: int) -> str:
    depth = 0
    for index in range(open_paren, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index]
    return text[open_paren + 1 :]


def _pointer_names(text: str) -> set[str]:
    """Names this text declares as pointers.

    A `Type|Kind|Mode|State|Code`-suffixed identifier compared against 0 is a null
    check, not a raw discriminant, whenever the identifier is a pointer. The retail
    source model deliberately names pointer members and locals after the state object
    they reach (`nationState`, `g_pGlobalMapState`, `terrainStateTable`), so the
    name-shaped detector cannot tell them apart without the declaration.
    """
    return {match.group("name") for match in _POINTER_DECL_RE.finditer(text)}


_POINTER_DECL_RE = re.compile(r"[\w>\]]\s*\*\s*(?:const\s+)?(?P<name>[A-Za-z_]\w*)\b\s*(?:=|;|\)|,|\[)")


def _header_pointer_names(repo_root: Path) -> set[str]:
    names: set[str] = set()
    for path in _manual_paths(repo_root):
        if path.suffix != ".h":
            continue
        names |= _pointer_names(path.read_text(encoding="utf-8", errors="replace"))
    return names


def collect_findings(repo_root: Path, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    categories = config["categories"]
    occurrences: Counter[tuple[str, str, str, str]] = Counter()
    header_pointers = _header_pointer_names(repo_root)

    def add(category: str, path: Path, line: int, detail: str, source: str) -> None:
        policy = categories[category]
        relative_path = path.relative_to(repo_root).as_posix()
        normalized = re.sub(r"\s+", " ", source.strip())
        occurrence_key = (category, relative_path, detail, normalized)
        occurrence = occurrences[occurrence_key]
        occurrences[occurrence_key] += 1
        findings.append(
            Finding(
                category,
                relative_path,
                line,
                detail,
                source.strip(),
                str(policy["classification"]),
                str(policy["owner"]),
                occurrence,
            )
        )

    for path in _manual_paths(repo_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        pointer_names = header_pointers | _pointer_names(text)
        for line_number, source in enumerate(text.splitlines(), 1):
            code = source.split("//", 1)[0]
            if not code.strip():
                continue
            for match in _NESTED_CAST_RE.finditer(code):
                add(
                    "nested_integral_cast",
                    path,
                    line_number,
                    f"{match.group('inner')} -> {match.group('outer')}",
                    source,
                )
            for match in _PREDICATE_CAST_RE.finditer(code):
                expression = _balanced_argument(code, match.end() - 1)
                without_cast_types = re.sub(r"static_cast\s*<[^>]+>", "", expression)
                if _COMPARISON_RE.search(without_cast_types) is None:
                    continue
                add(
                    "predicate_storage_cast",
                    path,
                    line_number,
                    f"predicate -> {match.group('type')}",
                    source,
                )
            for match in _DISCRIMINANT_RE.finditer(code):
                if (
                    match.group("literal") == "0"
                    and match.group("operator") in ("==", "!=")
                    and match.group("name") in pointer_names
                ):
                    # Null check on a pointer, not a discriminant comparison.
                    continue
                add(
                    "raw_discriminant_literal",
                    path,
                    line_number,
                    f"{match.group('name')} {match.group('operator')} {match.group('literal')}",
                    source,
                )
            for match in _NATIVE_CAST_RE.finditer(code):
                add(
                    "native_integral_boundary",
                    path,
                    line_number,
                    f"game scalar -> {match.group('type')}",
                    source,
                )
    return sorted(findings, key=lambda row: (row.category, row.path, row.line, row.detail))


def _baseline_payload(findings: list[Finding]) -> dict:
    return {
        "format_version": FORMAT_VERSION,
        "fingerprints": sorted(finding.fingerprint for finding in findings),
    }


def _marker_addresses(repo_root: Path) -> set[str]:
    """Every reccmp address marker manual source claims."""
    addresses: set[str] = set()
    marker = re.compile(r"//\s*(?:FUNCTION|SYNTHETIC|VTABLE|GLOBAL|STRING|LIBRARY):\s*IMPERIALISM\s+(0x[0-9a-fA-F]+)")
    for path in _manual_paths(repo_root):
        for match in marker.finditer(path.read_text(encoding="utf-8", errors="replace")):
            addresses.add(match.group(1).lower())
    return addresses


def check_bool_inventory(repo_root: Path) -> list[str]:
    """The predicate inventory must stay anchored to real source.

    Every row names the retail address whose listing supplied the classification. A
    row whose address no longer appears in manual source is stale evidence, which is
    worse than no row at all.
    """
    path = repo_root / BOOL_INVENTORY_PATH
    if not path.exists():
        return [f"{BOOL_INVENTORY_PATH}: missing"]
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    required = {"domain", "location", "address", "canonical_type", "classification", "evidence"}
    errors: list[str] = []
    if not rows:
        return [f"{BOOL_INVENTORY_PATH}: no rows"]
    missing_columns = required - set(rows[0])
    if missing_columns:
        return [f"{BOOL_INVENTORY_PATH}: missing column(s) {sorted(missing_columns)}"]
    known = _marker_addresses(repo_root)
    for index, row in enumerate(rows, 2):
        for column in sorted(required):
            if not (row.get(column) or "").strip():
                errors.append(f"{BOOL_INVENTORY_PATH}:{index}: empty {column}")
        # A row may cover a whole virtual family, listing its addresses separated by "/".
        for address in (row.get("address") or "").strip().lower().split("/"):
            address = address.strip()
            if address.startswith("0x") and address not in known:
                errors.append(
                    f"{BOOL_INVENTORY_PATH}:{index}: {address} is not claimed by any manual marker"
                )
    return errors


def render_report(findings: list[Finding], config: dict) -> str:
    counts = Counter(finding.category for finding in findings)
    clang_tidy = config["clang_tidy"]
    native_findings = {
        finding.fingerprint: finding
        for finding in findings
        if finding.category == "native_integral_boundary"
    }
    native_reviews = config.get("native_integral_reviews", {})
    discriminant_reviews = config.get(DISCRIMINANT_REVIEWS_KEY, {})
    discriminant_families = sorted(
        {finding.family for finding in findings if finding.category == "raw_discriminant_literal"}
    )
    missing_families = [name for name in discriminant_families if name not in discriminant_reviews]
    stale_families = sorted(set(discriminant_reviews) - set(discriminant_families))
    if missing_families or stale_families:
        details = []
        if missing_families:
            details.append(f"unreviewed={','.join(missing_families)}")
        if stale_families:
            details.append(f"stale={','.join(stale_families)}")
        raise ValueError(f"discriminant reviews do not match findings ({'; '.join(details)})")
    for family, review in discriminant_reviews.items():
        if not review.get("classification") or not review.get("evidence"):
            raise ValueError(f"incomplete discriminant review for {family}")
    predicate_findings = {
        finding.fingerprint: finding
        for finding in findings
        if finding.category == "predicate_storage_cast"
    }
    predicate_reviews = config.get(PREDICATE_REVIEWS_KEY, {})
    missing_predicates = sorted(set(predicate_findings) - set(predicate_reviews))
    stale_predicates = sorted(set(predicate_reviews) - set(predicate_findings))
    if missing_predicates or stale_predicates:
        details = []
        if missing_predicates:
            details.append(
                "unreviewed="
                + ",".join(
                    f"{fingerprint}@{predicate_findings[fingerprint].path}:"
                    f"{predicate_findings[fingerprint].line}"
                    for fingerprint in missing_predicates
                )
            )
        if stale_predicates:
            details.append(f"stale={','.join(stale_predicates)}")
        raise ValueError(f"predicate storage reviews do not match findings ({'; '.join(details)})")
    for fingerprint, review in predicate_reviews.items():
        if not review.get("classification") or not review.get("evidence"):
            raise ValueError(f"incomplete predicate storage review for {fingerprint}")
    missing_reviews = sorted(set(native_findings) - set(native_reviews))
    stale_reviews = sorted(set(native_reviews) - set(native_findings))
    if missing_reviews or stale_reviews:
        details = []
        if missing_reviews:
            details.append(f"missing={','.join(missing_reviews)}")
        if stale_reviews:
            details.append(f"stale={','.join(stale_reviews)}")
        raise ValueError(f"native integral reviews do not match findings ({'; '.join(details)})")
    for fingerprint, review in native_reviews.items():
        if not review.get("classification") or not review.get("evidence"):
            raise ValueError(f"incomplete native integral review for {fingerprint}")
    lines = [
        "<!-- AUTO-GENERATED by tools/workflow/scalar_type_audit.py; DO NOT EDIT. -->",
        "# Scalar type audit",
        "",
        "This source-only audit scans manually owned `include/game` and `src/game` files;",
        "generated translation units and retail library source are excluded. Every finding",
        "has a reviewed classification and a durable Beads owner in",
        f"`{CONFIG_PATH}`. The fingerprint baseline rejects newly introduced patterns.",
        "",
        "`raw_discriminant_literal` deliberately does not report `== 0` / `!= 0` on an",
        "identifier the manual source declares as a pointer: the recovered model names",
        "pointer members and locals after the state object they reach (`nationState`,",
        "`g_pGlobalMapState`, `terrainStateTable`), so those comparisons are null checks",
        "rather than domain discriminants.",
        "",
        "## Summary",
        "",
        f"- Findings: {len(findings)}",
    ]
    for category in sorted(counts):
        lines.append(f"- `{category}`: {counts[category]}")
    lines.extend(
        (
            "",
            "## clang-tidy evaluation",
            "",
            f"- Status: `{clang_tidy['status']}`",
            *(
                [f"- Version: `{clang_tidy['version']}`"]
                if "version" in clang_tidy
                else []
            ),
            f"- Decision: `{clang_tidy['decision']}`",
            "- Evaluated checks: " + ", ".join(f"`{item}`" for item in clang_tidy["evaluated_checks"]),
            *([f"- Sample: {clang_tidy['sample']}"] if "sample" in clang_tidy else []),
            *([f"- Result: {clang_tidy['result']}"] if "result" in clang_tidy else []),
            f"- Rationale: {clang_tidy['rationale']}",
            "",
            "## Reviewed native integral boundaries",
            "",
            "Every native cast is individually reviewed. Fingerprints deliberately include the",
            "source expression, so a changed boundary must be reviewed again instead of inheriting",
            "a stale category-level approval.",
            "",
            "| Fingerprint | Source | Classification | Evidence |",
            "| --- | --- | --- | --- |",
            *(
                f"| `{fingerprint}` | `{native_findings[fingerprint].path}:"
                f"{native_findings[fingerprint].line}` | `"
                f"{review['classification']}` | {review['evidence']} |"
                for fingerprint, review in native_reviews.items()
            ),
            "",
            "## Reviewed predicate storage boundaries",
            "",
            "Each `predicate_storage_cast` is reviewed at its own site, because whether a",
            "predicate may become `bool` depends on that site's storage width and return",
            "ABI, not on the class. The fingerprint covers the source expression, so an",
            "edited boundary must be reviewed again. The durable prose record of these",
            f"decisions -- including the ones that were measured and reverted -- is",
            f"`{BOOL_INVENTORY_PATH}`.",
            "",
            "| Source | Detail | Classification | Evidence |",
            "| --- | --- | --- | --- |",
            *(
                f"| `{predicate_findings[fingerprint].path}:{predicate_findings[fingerprint].line}`"
                f" | {predicate_findings[fingerprint].detail} | "
                f"`{predicate_reviews[fingerprint]['classification']}` | "
                f"{predicate_reviews[fingerprint]['evidence']} |"
                for fingerprint in sorted(
                    predicate_findings,
                    key=lambda key: (predicate_findings[key].path, predicate_findings[key].line),
                )
            ),
            "",
            "## Reviewed discriminant families",
            "",
            "Every identifier a `raw_discriminant_literal` finding compares carries its own",
            "reviewed classification and evidence. A new identifier fails the check until it",
            "is classified, and a family that stops appearing must be removed.",
            "",
            "| Family | Sites | Classification | Evidence |",
            "| --- | --- | --- | --- |",
            *(
                f"| `{family}` | "
                f"{sum(1 for row in findings if row.category == 'raw_discriminant_literal' and row.family == family)}"
                f" | `{discriminant_reviews[family]['classification']}` | "
                f"{discriminant_reviews[family]['evidence']} |"
                for family in discriminant_families
            ),
            "",
            "## Findings",
            "",
            "| Fingerprint | Category | Source | Detail | Classification | Owner |",
            "| --- | --- | --- | --- | --- | --- |",
        )
    )
    for finding in findings:
        detail = finding.detail.replace("|", "\\|")
        classification = finding.classification
        owner = finding.owner
        if finding.category == "raw_discriminant_literal":
            review = discriminant_reviews[finding.family]
            classification = str(review["classification"])
            owner = str(review.get("owner", owner))
        elif finding.category == "predicate_storage_cast":
            review = predicate_reviews[finding.fingerprint]
            classification = str(review["classification"])
            owner = str(review.get("owner", owner))
        lines.append(
            f"| `{finding.fingerprint}` | `{finding.category}` | "
            f"`{finding.path}:{finding.line}` | {detail} | "
            f"`{classification}` | `{owner}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="rewrite report and baseline")
    action.add_argument("--check", action="store_true", help="fail on report or baseline drift")
    args = parser.parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=2)
    try:
        config = _load_config(repo_root)
        inventory_errors = check_bool_inventory(repo_root)
        if inventory_errors:
            raise ValueError("; ".join(inventory_errors))
        findings = collect_findings(repo_root, config)
        report = render_report(findings, config)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"Scalar type audit failed: {exc}")
        return 1
    baseline = _baseline_payload(findings)
    report_path = repo_root / REPORT_PATH
    baseline_path = repo_root / BASELINE_PATH
    if args.write:
        report_path.write_text(report, encoding="utf-8")
        baseline_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Wrote scalar type audit: {len(findings)} classified findings")
        return 0
    if args.check:
        current_report = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
        if current_report != report:
            print(f"Scalar type audit failed: {REPORT_PATH} is stale")
            return 1
        if not baseline_path.is_file():
            print(f"Scalar type audit failed: missing {BASELINE_PATH}")
            return 1
        committed = json.loads(baseline_path.read_text(encoding="utf-8"))
        known = set(committed.get("fingerprints", []))
        current = set(baseline["fingerprints"])
        added = sorted(current - known)
        removed = sorted(known - current)
        if added:
            print(f"Scalar type audit failed: {len(added)} new finding(s):")
            by_fingerprint = {finding.fingerprint: finding for finding in findings}
            for fingerprint in added[:20]:
                finding = by_fingerprint[fingerprint]
                print(f"  {fingerprint} {finding.path}:{finding.line} {finding.detail}")
            return 1
        print(
            f"Scalar type audit passed: {len(findings)} classified findings; "
            f"{len(removed)} baseline finding(s) removed"
        )
        return 0
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
