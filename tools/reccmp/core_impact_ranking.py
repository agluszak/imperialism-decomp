#!/usr/bin/env python3
"""Prioritize core matching work by impact: size * (1 - similarity)."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from ruamel.yaml import YAML

from symbol_buckets import classify_name, parse_function_symbols, parse_reccmp_report


DEFAULT_EXCLUDED_BUCKETS = {
    "crt_likely",
    "mfc_likely",
    "directx_audio_net_likely",
    "wrapper_likely",
    "thunk",
}

WRAPPER_HINTS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Afx",
        re.compile(
            r"(Afx|Mfc|CWnd::|CDocument::|CFrameWnd::|CObArray::|CFileException::|"
            r"CStatusBarCtrl::|CToolBarCtrl::|CTreeCtrl::|CListCtrl::)",
            re.IGNORECASE,
        ),
    ),
    (
        "Crt",
        re.compile(
            r"(CRT|WinMainCRT|StructuredException|Tls|Heap|malloc|free|new|delete|"
            r"memcpy|memset|memcmp|strlen|strcpy|strcmp|qsort|bsearch)",
            re.IGNORECASE,
        ),
    ),
    (
        "Dx",
        re.compile(
            r"(DirectSound|DPlay|WINMM|mmio|mci|Wave|Midi|Joystick|auxGet|timeGetTime)",
            re.IGNORECASE,
        ),
    ),
]


@dataclass(frozen=True)
class RankedFunction:
    address: int
    name: str
    size: int
    similarity_pct: float
    impact: float
    bucket: str
    module: str
    ignored_by_name: bool
    compared: bool


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--symbols-csv", default=str(repo_root / "config" / "symbols.csv"))
    parser.add_argument(
        "--roadmap-csv",
        default=str(repo_root / "build-msvc500" / "reccmp_roadmap.csv"),
    )
    parser.add_argument(
        "--report-json",
        default=str(repo_root / "build-msvc500" / "reccmp_report.json"),
    )
    parser.add_argument("--project-yml", default=str(repo_root / "reccmp-project.yml"))
    parser.add_argument("--top", type=int, default=40)
    parser.add_argument("--wrapper-top", type=int, default=20)
    parser.add_argument(
        "--exclude-bucket",
        action="append",
        default=[],
        help=(
            "Bucket to exclude from core scope (repeatable). "
            "Defaults: crt_likely,mfc_likely,directx_audio_net_likely,wrapper_likely,thunk"
        ),
    )
    parser.add_argument(
        "--include-ignored",
        action="store_true",
        help="Include functions currently listed under report.ignore_functions.",
    )
    parser.add_argument(
        "--include-unscored",
        action="store_true",
        help="Include functions missing reccmp similarity (treated as 0%%).",
    )
    parser.add_argument("--min-size", type=int, default=8)
    parser.add_argument("--json-out", default="")
    parser.add_argument("--csv-out", default="")
    return parser.parse_args()


def load_ignore_names(project_yml: Path, target: str) -> set[str]:
    yaml = YAML(typ="safe")
    raw = yaml.load(project_yml.read_text(encoding="utf-8")) or {}
    targets = raw.get("targets") or {}
    tgt = targets.get(target) or {}
    report = tgt.get("report") or {}
    names = report.get("ignore_functions") or []
    return {str(name) for name in names}


def load_roadmap_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing roadmap CSV: {path}")
    out: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            if row.get("row_type") != "fun":
                continue
            if not (row.get("orig_addr") or "").strip():
                continue
            out.append(row)
    return out


def hint_prefix(name: str) -> str | None:
    for prefix, rx in WRAPPER_HINTS:
        if rx.search(name):
            return prefix
    return None


def main() -> int:
    args = parse_args()
    excluded_buckets = set(args.exclude_bucket or DEFAULT_EXCLUDED_BUCKETS)

    symbols = parse_function_symbols(Path(args.symbols_csv))
    symbol_by_addr = {sym.address: sym for sym in symbols}
    similarity_by_addr = parse_reccmp_report(Path(args.report_json))
    ignore_names = load_ignore_names(Path(args.project_yml), args.target)
    roadmap_rows = load_roadmap_rows(Path(args.roadmap_csv))

    ranked: list[RankedFunction] = []
    scope_total = 0
    skipped_by_bucket = 0
    skipped_by_name_ignore = 0
    skipped_by_missing_score = 0
    skipped_by_size = 0

    wrapper_candidates: list[RankedFunction] = []

    for row in roadmap_rows:
        addr = int(str(row["orig_addr"]).strip(), 10)
        row_name = (row.get("name") or "").strip()
        module = (row.get("module") or "").strip()

        sym = symbol_by_addr.get(addr)
        name = sym.name if sym else row_name
        bucket = classify_name(name)
        size = 0
        size_text = (row.get("size") or "").strip()
        if size_text:
            try:
                size = int(size_text, 10)
            except ValueError:
                size = 0
        if size <= 0 and sym and sym.size:
            size = sym.size

        if size < args.min_size:
            skipped_by_size += 1
            continue

        similarity = similarity_by_addr.get(addr)
        compared = similarity is not None
        if similarity is None and not args.include_unscored:
            skipped_by_missing_score += 1
            continue
        similarity_pct = 0.0 if similarity is None else max(0.0, min(100.0, similarity))

        ignored_by_name = name in ignore_names or row_name in ignore_names

        if bucket in excluded_buckets:
            skipped_by_bucket += 1
            if bucket in {"wrapper_likely", "thunk"}:
                prefix = hint_prefix(name)
                if prefix and not name.startswith(prefix):
                    wrapper_candidates.append(
                        RankedFunction(
                            address=addr,
                            name=name,
                            size=size,
                            similarity_pct=similarity_pct,
                            impact=float(size) * (1.0 - (similarity_pct / 100.0)),
                            bucket=bucket,
                            module=module,
                            ignored_by_name=ignored_by_name,
                            compared=compared,
                        )
                    )
            continue

        if ignored_by_name and not args.include_ignored:
            skipped_by_name_ignore += 1
            continue

        scope_total += 1
        ranked.append(
            RankedFunction(
                address=addr,
                name=name,
                size=size,
                similarity_pct=similarity_pct,
                impact=float(size) * (1.0 - (similarity_pct / 100.0)),
                bucket=bucket,
                module=module,
                ignored_by_name=ignored_by_name,
                compared=compared,
            )
        )

    ranked.sort(key=lambda x: (x.impact, x.size, -x.similarity_pct), reverse=True)
    wrapper_candidates.sort(key=lambda x: (x.size, x.impact), reverse=True)

    print(f"Target: {args.target}")
    print(f"Core scope buckets excluded: {', '.join(sorted(excluded_buckets))}")
    print(
        "Rows considered: {} | core candidates: {} | skipped(size/bucket/ignored/missing_score): "
        "{}/{}/{}/{}".format(
            len(roadmap_rows),
            scope_total,
            skipped_by_size,
            skipped_by_bucket,
            skipped_by_name_ignore,
            skipped_by_missing_score,
        )
    )
    print("")
    print(f"Top {min(args.top, len(ranked))} by impact = size * (1 - similarity):")
    for i, entry in enumerate(ranked[: args.top], start=1):
        print(
            "{:>2}. 0x{:08x} size={:<5d} sim={:>6.2f}% impact={:>8.2f}  {:<16s}  {}".format(
                i,
                entry.address,
                entry.size,
                entry.similarity_pct,
                entry.impact,
                entry.bucket,
                entry.name,
            )
        )

    if wrapper_candidates:
        print("")
        print(f"Wrapper relabel candidates ({min(args.wrapper_top, len(wrapper_candidates))} shown):")
        for entry in wrapper_candidates[: args.wrapper_top]:
            prefix = hint_prefix(entry.name)
            suggestion = f"{prefix}_{entry.name}" if prefix else entry.name
            print(
                "  0x{:08x} size={:<5d} {:<14s} {} -> {}".format(
                    entry.address,
                    entry.size,
                    entry.bucket,
                    entry.name,
                    suggestion,
                )
            )

    if args.csv_out:
        out_path = Path(args.csv_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8", newline="") as fd:
            writer = csv.writer(fd)
            writer.writerow(
                [
                    "address",
                    "name",
                    "size",
                    "similarity_pct",
                    "impact",
                    "bucket",
                    "module",
                    "ignored_by_name",
                    "compared",
                ]
            )
            for entry in ranked:
                writer.writerow(
                    [
                        f"0x{entry.address:08x}",
                        entry.name,
                        entry.size,
                        f"{entry.similarity_pct:.4f}",
                        f"{entry.impact:.4f}",
                        entry.bucket,
                        entry.module,
                        "1" if entry.ignored_by_name else "0",
                        "1" if entry.compared else "0",
                    ]
                )
        print(f"\nWrote CSV: {out_path}")

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": args.target,
            "excluded_buckets": sorted(excluded_buckets),
            "roadmap_fun_rows": len(roadmap_rows),
            "core_candidates": scope_total,
            "skipped": {
                "size": skipped_by_size,
                "bucket": skipped_by_bucket,
                "name_ignore": skipped_by_name_ignore,
                "missing_score": skipped_by_missing_score,
            },
            "ranked": [asdict(x) for x in ranked],
            "wrapper_relabel_candidates": [asdict(x) for x in wrapper_candidates],
        }
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"Wrote JSON: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
