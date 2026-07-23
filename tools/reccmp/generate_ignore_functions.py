#!/usr/bin/env python3
"""Generate and optionally apply reccmp ignore lists from library EVIDENCE.

An address is ignored only when it carries library evidence (a reviewed row in
config/reviewed_library_identities.csv or MSVC500 oracle provenance in
config/original_entities.csv, minus the gamecode allowlist) — never because its
provisional name looks library-shaped (Hard Rule 6). Name-regex selection hid
461 real game functions (~29KB) from the report and the core-impact ranking.

This writes a patchable YAML block for `report.ignore_functions` (names) and
optionally `ghidra.ignore_functions` (addresses).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.common.repo import repo_root_from_file
from tools.reccmp.symbol_buckets import (
    classify_name,
    load_library_evidence,
    parse_function_symbols,
    parse_reccmp_report,
)


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--symbols-csv", default=str(repo_root / "config" / "original_entities.csv"))
    parser.add_argument(
        "--report-json",
        default=str(repo_root / "build-msvc500" / "reccmp_report.json"),
        help="Optional reccmp report to filter by similarity threshold.",
    )
    parser.add_argument(
        "--include-thunks",
        action="store_true",
        help="Also ignore functions in the name-based 'thunk' bucket.",
    )
    parser.add_argument(
        "--max-similarity",
        type=float,
        default=None,
        help="Only include functions with similarity <= this percent (requires report JSON).",
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=0,
        help="Only include functions with size >= this value (size from symbols.csv).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply generated list directly to reccmp-project.yml.",
    )
    parser.add_argument(
        "--project-yml",
        default=str(repo_root / "reccmp-project.yml"),
        help="Path to reccmp-project.yml for --apply.",
    )
    parser.add_argument(
        "--update-ghidra-ignore",
        action="store_true",
        help="Also set ghidra.ignore_functions (address list) on --apply.",
    )
    parser.add_argument(
        "--output-yml",
        default=str(repo_root / "build-msvc500" / "ignore_functions_patch.yml"),
        help="Patchable YAML block output path.",
    )
    parser.add_argument(
        "--output-json",
        default=str(repo_root / "build-msvc500" / "ignore_functions_candidates.json"),
        help="Detailed candidate JSON output path.",
    )
    return parser.parse_args()


def format_patch_block(target: str, names: list[str], addrs: list[int], include_ghidra: bool) -> str:
    lines: list[str] = []
    lines.append("targets:")
    lines.append(f"  {target}:")
    lines.append("    report:")
    lines.append("      ignore_functions:")
    for name in names:
        lines.append(f"      - {json.dumps(name)}")
    if include_ghidra:
        lines.append("    ghidra:")
        lines.append("      ignore_functions:")
        for addr in addrs:
            lines.append(f"      - 0x{addr:08x}")
    return "\n".join(lines) + "\n"


def apply_to_project(
    project_path: Path, target: str, names: list[str], addrs: list[int], update_ghidra: bool
) -> None:
    from reccmp.project.config import ProjectFile

    project = ProjectFile.from_file(project_path)
    if target not in project.targets:
        raise KeyError(f"Target '{target}' not found in {project_path}")
    tgt = project.targets[target]
    tgt.report.ignore_functions = names
    if update_ghidra:
        tgt.ghidra.ignore_functions = addrs
    project.write_file(project_path)


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    evidence = load_library_evidence(repo_root)

    symbols = parse_function_symbols(Path(args.symbols_csv))
    score_by_addr = parse_reccmp_report(Path(args.report_json))

    candidates: list[dict] = []
    for symbol in symbols:
        bucket = evidence.get(symbol.address)
        if bucket is None:
            if not (args.include_thunks and classify_name(symbol.name) == "thunk"):
                continue
            bucket = "thunk"
        if symbol.size is not None and symbol.size < args.min_size:
            continue
        similarity = score_by_addr.get(symbol.address)
        if args.max_similarity is not None:
            if similarity is None or similarity > args.max_similarity:
                continue
        candidates.append(
            {
                "address": symbol.address,
                "name": symbol.name,
                "size": symbol.size,
                "bucket": bucket,
                "similarity": similarity,
            }
        )

    candidates.sort(key=lambda x: (x["bucket"], x["address"]))
    ignore_names = sorted({str(x["name"]) for x in candidates})
    ignore_addrs = sorted({int(x["address"]) for x in candidates})

    out_json = Path(args.output_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": args.target,
        "selection": "library_evidence" + ("+thunk" if args.include_thunks else ""),
        "evidence_address_count": len(evidence),
        "max_similarity": args.max_similarity,
        "min_size": args.min_size,
        "candidate_count": len(candidates),
        "ignore_name_count": len(ignore_names),
        "ignore_address_count": len(ignore_addrs),
        "candidates": candidates,
    }
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    out_yml = Path(args.output_yml)
    out_yml.parent.mkdir(parents=True, exist_ok=True)
    out_yml.write_text(
        format_patch_block(
            target=args.target,
            names=ignore_names,
            addrs=ignore_addrs,
            include_ghidra=args.update_ghidra_ignore,
        ),
        encoding="utf-8",
    )

    print(f"Library-evidence addresses: {len(evidence)}")
    print(f"Candidates: {len(candidates)}")
    print(f"report.ignore_functions names: {len(ignore_names)}")
    print(f"ghidra.ignore_functions addrs: {len(ignore_addrs)}")
    print(f"Wrote patch block: {out_yml}")
    print(f"Wrote details: {out_json}")

    if args.apply:
        project_path = Path(args.project_yml)
        apply_to_project(
            project_path=project_path,
            target=args.target,
            names=ignore_names,
            addrs=ignore_addrs,
            update_ghidra=args.update_ghidra_ignore,
        )
        print(f"Applied to: {project_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
