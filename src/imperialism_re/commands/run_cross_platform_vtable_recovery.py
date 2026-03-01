#!/usr/bin/env python3
"""
Run cross-platform macOS->Windows vtable recovery as one maintained pipeline command.

Pipeline stages:
  A) scan Windows static .rdata vtable candidates
  B) export macOS function fingerprints
  C) export Windows function fingerprints
  D) seed match by shared strings
  E) score/match vtables cross-platform and emit slot-map
  F) infer Windows name candidates from macOS vtable layout using slot-map
  G) propagate class naming by callgraph from matched virtual methods
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.xplat_vtable.export_fingerprints_macos import (
    run as run_export_fingerprints_macos,
)
from imperialism_re.core.xplat_vtable.export_fingerprints_windows import (
    run as run_export_fingerprints_windows,
)
from imperialism_re.core.xplat_vtable.match_vtables_cross_platform import (
    run as run_match_vtables_cross_platform,
)
from imperialism_re.core.xplat_vtable.propagate_class_callgraph import (
    run as run_propagate_class_callgraph,
)
from imperialism_re.core.xplat_vtable.scan_windows_static_vtables import (
    run as run_scan_windows_static_vtables,
)
from imperialism_re.core.xplat_vtable.seed_match_shared_strings import (
    run as run_seed_match_shared_strings,
)


def _run_subprocess(cmd: list[str]) -> int:
    print("[run]", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.stdout:
        print(cp.stdout.strip())
    if cp.stderr:
        print(cp.stderr.strip())
    return int(cp.returncode)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run cross-platform vtable recovery pipeline (macOS blueprint -> Windows slot map).",
    )
    ap.add_argument(
        "--windows-static-vtables-csv",
        default="tmp_decomp/windows_static_vtables.csv",
        help="Static Windows vtable scan output CSV.",
    )
    ap.add_argument(
        "--macos-fingerprints-csv",
        default="tmp_decomp/macos_func_fingerprints.csv",
        help="macOS fingerprints output CSV.",
    )
    ap.add_argument(
        "--windows-fingerprints-csv",
        default="tmp_decomp/windows_func_fingerprints.csv",
        help="Windows fingerprints output CSV.",
    )
    ap.add_argument(
        "--seed-matches-csv",
        default="tmp_decomp/seed_matches.csv",
        help="Seed matches output CSV.",
    )
    ap.add_argument(
        "--cross-platform-vtable-matches-csv",
        default="tmp_decomp/cross_platform_vtable_matches.csv",
        help="Cross-platform vtable match output CSV.",
    )
    ap.add_argument(
        "--windows-static-vtable-slot-map-csv",
        default="tmp_decomp/windows_static_vtable_slot_map.csv",
        help="Windows static slot-map CSV for infer_name_from_macos_vtable.",
    )
    ap.add_argument(
        "--windows-runtime-vtable-slot-writes-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_writes.csv",
        help="Runtime slot-write trace CSV (fallback lane).",
    )
    ap.add_argument(
        "--windows-runtime-vtable-slot-map-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_map.csv",
        help="Runtime slot-map CSV (fallback lane).",
    )
    ap.add_argument(
        "--macos-vtable-rename-candidates-csv",
        default="tmp_decomp/macos_vtable_rename_candidates_static.csv",
        help="Output CSV from infer_name_from_macos_vtable using static slot-map.",
    )
    ap.add_argument(
        "--callgraph-propagation-csv",
        default="tmp_decomp/callgraph_class_propagation.csv",
        help="Output callgraph class propagation CSV.",
    )
    ap.add_argument(
        "--macos-vtable-layout-csv",
        default="tmp_decomp/macos_vtable_layout.csv",
        help="Input macOS vtable layout CSV (from extract_macos_vtable_layout).",
    )
    ap.add_argument(
        "--macos-program-path",
        default="/Imperialism_macos",
        help="Ghidra program path for macOS binary.",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Optional comma-separated class filter applied to macOS fingerprints and vtable infer stage.",
    )
    ap.add_argument("--min-run", type=int, default=2, help="Minimum consecutive function pointers in .rdata run.")
    ap.add_argument("--max-gap", type=int, default=0, help="Allowed non-pointer dwords inside a run.")
    ap.add_argument("--only-unresolved", action="store_true", help="Restrict Windows fingerprint export to unresolved functions.")
    ap.add_argument("--addr-min", default="0x00400000", help="Windows function min address for fingerprint export.")
    ap.add_argument("--addr-max", default="0x006fffff", help="Windows function max address for fingerprint export.")
    ap.add_argument("--min-constant", default="256", help="Minimum scalar constant fingerprint value.")
    ap.add_argument("--max-constant", default="0x7FFF0000", help="Maximum scalar constant fingerprint value.")
    ap.add_argument("--max-macos-refs", type=int, default=5, help="Max macOS functions per shared string hash for medium-confidence seeds.")
    ap.add_argument("--max-win-refs", type=int, default=5, help="Max Windows functions per shared string hash for medium-confidence seeds.")
    ap.add_argument("--min-score", type=float, default=0.3, help="Minimum class match score for vtable alignment.")
    ap.add_argument("--max-abi-offset", type=int, default=4, help="Max ABI slot shift to test in vtable alignment.")
    ap.add_argument(
        "--confidence-filter",
        choices=["all", "low", "high", "medium"],
        default="all",
        help="Confidence filter passed to infer_name_from_macos_vtable.",
    )
    ap.add_argument(
        "--min-name-similarity",
        type=float,
        default=0.7,
        help="Minimum SequenceMatcher ratio for callgraph propagation rows.",
    )
    ap.add_argument(
        "--max-classes",
        type=int,
        default=0,
        help="Limit classes processed in propagation stage (0 = all).",
    )
    ap.add_argument("--skip-propagation", action="store_true", help="Skip stage G.")
    ap.add_argument(
        "--disable-runtime-fallback",
        action="store_true",
        help="Disable fallback to extract_windows_runtime_vtable_slot_writes when static scan yields zero rows.",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    classes_filter = {x.strip() for x in args.classes.split(",") if x.strip()}
    addr_min = int(str(args.addr_min), 0)
    addr_max = int(str(args.addr_max), 0)
    min_constant = int(str(args.min_constant), 0)
    max_constant = int(str(args.max_constant), 0)

    windows_static_vtables_csv = Path(args.windows_static_vtables_csv)
    if not windows_static_vtables_csv.is_absolute():
        windows_static_vtables_csv = root / windows_static_vtables_csv
    macos_fingerprints_csv = Path(args.macos_fingerprints_csv)
    if not macos_fingerprints_csv.is_absolute():
        macos_fingerprints_csv = root / macos_fingerprints_csv
    windows_fingerprints_csv = Path(args.windows_fingerprints_csv)
    if not windows_fingerprints_csv.is_absolute():
        windows_fingerprints_csv = root / windows_fingerprints_csv
    seed_matches_csv = Path(args.seed_matches_csv)
    if not seed_matches_csv.is_absolute():
        seed_matches_csv = root / seed_matches_csv
    cross_platform_matches_csv = Path(args.cross_platform_vtable_matches_csv)
    if not cross_platform_matches_csv.is_absolute():
        cross_platform_matches_csv = root / cross_platform_matches_csv
    windows_slot_map_csv = Path(args.windows_static_vtable_slot_map_csv)
    if not windows_slot_map_csv.is_absolute():
        windows_slot_map_csv = root / windows_slot_map_csv
    windows_runtime_slot_writes_csv = Path(args.windows_runtime_vtable_slot_writes_csv)
    if not windows_runtime_slot_writes_csv.is_absolute():
        windows_runtime_slot_writes_csv = root / windows_runtime_slot_writes_csv
    windows_runtime_slot_map_csv = Path(args.windows_runtime_vtable_slot_map_csv)
    if not windows_runtime_slot_map_csv.is_absolute():
        windows_runtime_slot_map_csv = root / windows_runtime_slot_map_csv
    rename_candidates_csv = Path(args.macos_vtable_rename_candidates_csv)
    if not rename_candidates_csv.is_absolute():
        rename_candidates_csv = root / rename_candidates_csv
    propagation_csv = Path(args.callgraph_propagation_csv)
    if not propagation_csv.is_absolute():
        propagation_csv = root / propagation_csv
    macos_vtable_layout_csv = Path(args.macos_vtable_layout_csv)
    if not macos_vtable_layout_csv.is_absolute():
        macos_vtable_layout_csv = root / macos_vtable_layout_csv

    # A
    scan_stats = run_scan_windows_static_vtables(
        root,
        out_csv=windows_static_vtables_csv,
        min_run=args.min_run,
        max_gap=args.max_gap,
    )
    scan_rows = int(scan_stats.get("rows", 0))
    static_lane_enabled = scan_rows > 0

    infer_slot_map_csv = windows_slot_map_csv
    if not static_lane_enabled and not args.disable_runtime_fallback:
        print(
            "[fallback] static .rdata scan yielded 0 rows; "
            "using runtime slot-write extraction for slot-map input"
        )
        runtime_cmd = [
            sys.executable,
            "-m",
            "imperialism_re.cli",
            "extract_windows_runtime_vtable_slot_writes",
            "--project-root",
            str(root),
            "--out-csv",
            str(windows_runtime_slot_writes_csv),
            "--out-best-csv",
            str(windows_runtime_slot_map_csv),
        ]
        if classes_filter:
            runtime_cmd.extend(["--classes", ",".join(sorted(classes_filter))])
        rc = _run_subprocess(runtime_cmd)
        if rc != 0:
            return rc
        infer_slot_map_csv = windows_runtime_slot_map_csv

    if static_lane_enabled:
        # B
        run_export_fingerprints_macos(
            root,
            out_csv=macos_fingerprints_csv,
            macos_program_path=args.macos_program_path,
            classes_filter=classes_filter,
            min_constant=min_constant,
            max_constant=max_constant,
        )
        # C
        run_export_fingerprints_windows(
            root,
            out_csv=windows_fingerprints_csv,
            only_unresolved=args.only_unresolved,
            addr_min=addr_min,
            addr_max=addr_max,
            min_constant=min_constant,
            max_constant=max_constant,
        )
        # D
        run_seed_match_shared_strings(
            macos_csv=macos_fingerprints_csv,
            windows_csv=windows_fingerprints_csv,
            out_csv=seed_matches_csv,
            max_macos_refs=args.max_macos_refs,
            max_win_refs=args.max_win_refs,
        )
        # E
        run_match_vtables_cross_platform(
            macos_vtable_csv=macos_vtable_layout_csv,
            windows_vtable_csv=windows_static_vtables_csv,
            seed_matches_csv=seed_matches_csv,
            out_csv=cross_platform_matches_csv,
            out_slot_map_csv=windows_slot_map_csv,
            min_score=args.min_score,
            max_abi_offset=args.max_abi_offset,
        )
    else:
        write_csv_rows(
            macos_fingerprints_csv,
            [],
            ["func_addr", "func_name", "class_name", "fingerprint_type", "fingerprint_value"],
        )
        write_csv_rows(
            windows_fingerprints_csv,
            [],
            ["func_addr", "func_name", "class_name", "fingerprint_type", "fingerprint_value"],
        )
        write_csv_rows(
            seed_matches_csv,
            [],
            [
                "mac_addr",
                "mac_name",
                "mac_class",
                "win_addr",
                "win_name",
                "win_class",
                "evidence_count",
                "match_type",
                "confidence",
                "evidence_hashes",
            ],
        )
        write_csv_rows(
            cross_platform_matches_csv,
            [],
            [
                "mac_class",
                "win_vtable_addr",
                "total_score",
                "mac_slot",
                "win_slot",
                "mac_method_name",
                "win_func_addr",
                "win_func_name",
                "abi_offset",
            ],
        )
        write_csv_rows(
            windows_slot_map_csv,
            [],
            [
                "class_name",
                "slot_index",
                "target_addr",
                "target_name",
                "confidence",
                "winner_writes",
                "total_writes",
                "candidate_count",
                "unique_writers",
                "slot_source",
            ],
        )
        print("[static_lane] skipped B-E because no static vtable candidates were found")
    # F (existing command)
    infer_cmd = [
        sys.executable,
        "-m",
        "imperialism_re.cli",
        "infer_name_from_macos_vtable",
        "--project-root",
        str(root),
        "--vtable-layout-csv",
        str(macos_vtable_layout_csv),
        "--windows-slot-map-csv",
        str(infer_slot_map_csv),
        "--out-csv",
        str(rename_candidates_csv),
        "--confidence-filter",
        args.confidence_filter,
    ]
    if classes_filter:
        infer_cmd.extend(["--classes", ",".join(sorted(classes_filter))])
    rc = _run_subprocess(infer_cmd)
    if rc != 0:
        return rc

    # G
    if not args.skip_propagation and static_lane_enabled:
        run_propagate_class_callgraph(
            root,
            vtable_matches_csv=cross_platform_matches_csv,
            macos_fingerprints_csv=macos_fingerprints_csv,
            out_csv=propagation_csv,
            min_name_similarity=args.min_name_similarity,
            max_classes=args.max_classes,
        )

    print("[done] run_cross_platform_vtable_recovery complete")
    print(f"[out] windows_static_vtables_csv={windows_static_vtables_csv}")
    print(f"[out] macos_fingerprints_csv={macos_fingerprints_csv}")
    print(f"[out] windows_fingerprints_csv={windows_fingerprints_csv}")
    print(f"[out] seed_matches_csv={seed_matches_csv}")
    print(f"[out] cross_platform_matches_csv={cross_platform_matches_csv}")
    print(f"[out] windows_slot_map_csv={windows_slot_map_csv}")
    if infer_slot_map_csv != windows_slot_map_csv:
        print(f"[out] runtime_fallback_slot_map_csv={infer_slot_map_csv}")
    print(f"[out] macos_vtable_rename_candidates_csv={rename_candidates_csv}")
    if not args.skip_propagation and static_lane_enabled:
        print(f"[out] callgraph_propagation_csv={propagation_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
