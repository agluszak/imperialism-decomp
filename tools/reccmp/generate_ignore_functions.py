#!/usr/bin/env python3
"""Generate and optionally apply reccmp ignore lists from symbol buckets.

This writes a patchable YAML block for `report.ignore_functions` (names) and
optionally `ghidra.ignore_functions` (addresses).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from symbol_buckets import classify_name, parse_function_symbols, parse_reccmp_report


DEFAULT_BUCKETS = ["crt_likely", "mfc_likely", "directx_audio_net_likely", "wrapper_likely"]


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--symbols-csv", default=str(repo_root / "config" / "symbols.csv"))
    parser.add_argument(
        "--report-json",
        default=str(repo_root / "build-msvc500" / "reccmp_report.json"),
        help="Optional reccmp report to filter by similarity threshold.",
    )
    parser.add_argument(
        "--include-bucket",
        action="append",
        default=[],
        help="Bucket name to include (repeatable). Defaults to CRT/MFC/DirectX-audio-net/wrapper buckets.",
    )
    parser.add_argument(
        "--exclude-bucket",
        action="append",
        default=[],
        help="Bucket name to exclude (repeatable).",
    )
    parser.add_argument(
        "--include-thunks",
        action="store_true",
        help="Include the 'thunk' bucket in ignore candidates.",
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


def select_buckets(args: argparse.Namespace) -> set[str]:
    buckets = set(args.include_bucket or DEFAULT_BUCKETS)
    if args.include_thunks:
        buckets.add("thunk")
    buckets -= set(args.exclude_bucket)
    return buckets


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
    buckets = select_buckets(args)

    symbols = parse_function_symbols(Path(args.symbols_csv))
    score_by_addr = parse_reccmp_report(Path(args.report_json))

    candidates: list[dict] = []
    for symbol in symbols:
        bucket = classify_name(symbol.name)
        if bucket not in buckets:
            continue
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
        "selected_buckets": sorted(buckets),
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

    print(f"Selected buckets: {', '.join(sorted(buckets))}")
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
