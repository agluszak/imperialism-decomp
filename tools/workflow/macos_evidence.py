#!/usr/bin/env python3
"""Normalize Mac CodeWarrior class and symbol evidence for Windows decomp slices."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path

DEFAULT_DUMP_DIR = Path("/home/agluszak/Downloads/imperialism.7z/Imperialism/dump")


@dataclass(frozen=True)
class SymbolRecord:
    owner: str
    method: str
    signature: str
    demangled: str
    raw: str
    source: str
    line: int
    kind: str
    confidence: str


def default_workspace(repo_root: Path) -> Path:
    return (repo_root.parent / "imperialism_knowledge" / "macos_codewarrior").resolve()


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def strip_codewarrior_noise(symbol: str) -> str:
    cleaned = symbol.strip().strip("\x00")
    cleaned = cleaned.removeprefix("$")
    cleaned = cleaned.strip()
    cleaned = cleaned.rstrip("|,")
    cleaned = re.sub(r"[`'\"]+$", "", cleaned)
    cleaned = re.sub(r"^[\x20-\x2f0-9A-Za-z]?\.", "", cleaned)
    return cleaned.strip()


def normalize_demangled(value: str) -> str:
    cleaned = value.strip().rstrip("|,")
    cleaned = re.sub(r"[`'\"]+$", "", cleaned)
    cleaned = re.sub(r"::[\x20-\x2f0-9A-Za-z]?\.", "::", cleaned)
    return cleaned


def parse_demangled_symbol(value: str) -> tuple[str, str, str] | None:
    cleaned = normalize_demangled(value)
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_:<>]*)::(.+?)(\(.*)$", cleaned)
    if not match:
        return None
    owner = match.group(1)
    method = match.group(2)
    signature = match.group(3)
    if not owner or not method:
        return None
    return owner, method, signature


def classify_method(owner: str, method: str) -> str:
    if method.startswith("~") or "__dt__" in method:
        return "destructor"
    if method.startswith("__ct__") or method in {owner, f"I{owner}", "_DefaultConstructor"}:
        return "constructor"
    if method in {"GetClassDescStatic", "GetClassDescDynamic"}:
        return "classdesc"
    return "method"


def demangle_raw_symbol(raw_symbol: str) -> str:
    cleaned = strip_codewarrior_noise(raw_symbol)
    if not cleaned or "__" not in cleaned:
        return ""
    try:
        cp = subprocess.run(
            ["cwdemangle", "--mw-extensions", cleaned],
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return ""
    if cp.returncode != 0:
        return ""
    return cp.stdout.strip()


def collect_classes(dump_dir: Path) -> list[str]:
    classes = set()
    for raw in read_lines(dump_dir / "classes.txt"):
        item = raw.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item):
            classes.add(item)
    for raw in read_lines(dump_dir / "plain_typeish_strings.txt"):
        item = raw.strip()
        if re.fullmatch(r"[TC][A-Z][A-Za-z0-9_]{2,}", item):
            classes.add(item)
    return sorted(classes)


def collect_symbols(dump_dir: Path) -> list[SymbolRecord]:
    records: list[SymbolRecord] = []
    seen: set[tuple[str, str, str, str]] = set()

    for line_no, line in enumerate(read_lines(dump_dir / "cw_symbols.demangled"), start=1):
        parsed = parse_demangled_symbol(line)
        if parsed is None:
            continue
        owner, method, signature = parsed
        demangled = f"{owner}::{method}{signature}"
        key = (owner, method, signature)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            SymbolRecord(
                owner=owner,
                method=method,
                signature=signature,
                demangled=demangled,
                raw="",
                source="cw_symbols.demangled",
                line=line_no,
                kind=classify_method(owner, method),
                confidence="high",
            )
        )

    for line_no, line in enumerate(read_lines(dump_dir / "cw_symbols.raw"), start=1):
        demangled_raw = demangle_raw_symbol(line)
        parsed = parse_demangled_symbol(demangled_raw)
        if parsed is None:
            continue
        owner, method, signature = parsed
        demangled = f"{owner}::{method}{signature}"
        key = (owner, method, signature)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            SymbolRecord(
                owner=owner,
                method=method,
                signature=signature,
                demangled=demangled,
                raw=strip_codewarrior_noise(line),
                source="cw_symbols.raw",
                line=line_no,
                kind=classify_method(owner, method),
                confidence="medium",
            )
        )
    return records


def write_outputs(workspace: Path, classes: list[str], symbols: list[SymbolRecord]) -> Path:
    evidence_dir = workspace / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    write_csv(evidence_dir / "classes.csv", ["class_name"], [{"class_name": cls} for cls in classes])
    symbol_rows = [
        {
            "owner": rec.owner,
            "method": rec.method,
            "signature": rec.signature,
            "demangled": rec.demangled,
            "raw": rec.raw,
            "source": rec.source,
            "line": rec.line,
            "kind": rec.kind,
            "confidence": rec.confidence,
        }
        for rec in symbols
    ]
    write_csv(
        evidence_dir / "symbols.csv",
        ["owner", "method", "signature", "demangled", "raw", "source", "line", "kind", "confidence"],
        symbol_rows,
    )

    by_owner: dict[str, list[SymbolRecord]] = defaultdict(list)
    for rec in symbols:
        by_owner[rec.owner].append(rec)
    summary_rows = []
    for owner in sorted(by_owner):
        methods = by_owner[owner]
        kind_counts = Counter(rec.kind for rec in methods)
        summary_rows.append(
            {
                "class_name": owner,
                "method_count": len(methods),
                "constructor_count": kind_counts["constructor"],
                "destructor_count": kind_counts["destructor"],
                "classdesc_count": kind_counts["classdesc"],
            }
        )
    write_csv(
        evidence_dir / "class_methods.csv",
        ["class_name", "method_count", "constructor_count", "destructor_count", "classdesc_count"],
        summary_rows,
    )

    summary = {
        "workspace": str(workspace),
        "classes": len(classes),
        "symbols": len(symbols),
        "owners": len(by_owner),
        "top_owners": [
            {"class_name": owner, "method_count": count}
            for owner, count in Counter(rec.owner for rec in symbols).most_common(30)
        ],
    }
    (evidence_dir / "class_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence_dir


def check_outputs(evidence_dir: Path) -> int:
    classes_path = evidence_dir / "classes.csv"
    symbols_path = evidence_dir / "symbols.csv"
    if not classes_path.exists() or not symbols_path.exists():
        print(f"Missing evidence outputs in {evidence_dir}", file=sys.stderr)
        return 1

    with classes_path.open("r", encoding="utf-8", newline="") as fd:
        classes = {row["class_name"] for row in csv.DictReader(fd)}
    with symbols_path.open("r", encoding="utf-8", newline="") as fd:
        symbols = list(csv.DictReader(fd))
    demangled = {row["demangled"] for row in symbols}

    expected_classes = {"TGreatPower", "TAutoGreatPower", "TAmtBar", "TShipAmtBar", "TTraderAmtBar"}
    expected_methods = {
        "TGreatPower::ReplyToDiplomacyOffers()",
        "TAutoGreatPower::CreateMission(eMissionType, long, TZone*, long)",
        "TAmtBar::SetAmt(short, short)",
        "TTraderAmtBar::AdjustForZero(short, short)",
    }
    errors = []
    missing_classes = sorted(expected_classes - classes)
    if missing_classes:
        errors.append(f"missing classes: {', '.join(missing_classes)}")
    missing_methods = sorted(expected_methods - demangled)
    if missing_methods:
        errors.append(f"missing methods: {', '.join(missing_methods)}")
    if len(classes) < 400:
        errors.append(f"class count too low: {len(classes)}")
    if len(symbols) < 4500:
        errors.append(f"symbol count too low: {len(symbols)}")

    print(f"Mac evidence classes: {len(classes)}")
    print(f"Mac evidence symbols: {len(symbols)}")
    if errors:
        print("Mac evidence check failed:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("Mac evidence check passed.")
    return 0


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    workspace = default_workspace(repo_root)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dump-dir",
        default=os.environ.get("MACOS_IMPERIALISM_DUMP", str(DEFAULT_DUMP_DIR)),
        help="Directory containing Mac dump files.",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("MACOS_CODEWARRIOR_WORKSPACE", str(workspace)),
        help="Persistent local workspace for Mac evidence outputs.",
    )
    parser.add_argument("--check", action="store_true", help="Validate previously generated evidence.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    dump_dir = resolve_repo_path(repo_root, args.dump_dir)
    workspace = resolve_repo_path(repo_root, args.workspace)
    evidence_dir = workspace / "evidence"

    if args.check:
        return check_outputs(evidence_dir)

    if not dump_dir.is_dir():
        raise SystemExit(f"Missing Mac dump directory: {dump_dir}")
    classes = collect_classes(dump_dir)
    symbols = collect_symbols(dump_dir)
    evidence_dir = write_outputs(workspace, classes, symbols)
    print(f"[saved] {evidence_dir}")
    print(f"[info] classes={len(classes)} symbols={len(symbols)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
