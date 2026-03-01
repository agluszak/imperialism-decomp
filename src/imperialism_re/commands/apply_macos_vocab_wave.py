#!/usr/bin/env python3
"""
Run a full macOS-vocabulary class wave using maintained commands.

Flow:
  1) build class gap map
  2) infer raw vtable candidates for selected classes
  3) generate conservative wave CSVs
  4) run run_wave_bundle with generated CSVs
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root


def _run(cmd: list[str]) -> int:
    print("[run]", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.stdout:
        print(cp.stdout.strip())
    if cp.stderr:
        print(cp.stderr.strip())
    return cp.returncode


def _read_rows(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.exists():
        return []
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _select_classes_from_gap(gap_rows: list[dict[str, str]], top_classes: int) -> list[str]:
    rank_map: dict[str, int] = {}
    for row in gap_rows:
        class_name = (row.get("class_name") or "").strip()
        if not class_name:
            continue
        try:
            rank = int((row.get("class_rank") or "").strip() or "999999")
        except ValueError:
            rank = 999999
        prev = rank_map.get(class_name)
        if prev is None or rank < prev:
            rank_map[class_name] = rank
    classes = [cls for cls, _rank in sorted(rank_map.items(), key=lambda x: (x[1], x[0]))]
    if top_classes > 0:
        return classes[:top_classes]
    return classes


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a conservative macOS vocabulary wave.")
    ap.add_argument("--batch-tag", required=True, help="Wave batch tag for run_wave_bundle.")
    ap.add_argument(
        "--gap-map-csv",
        default="tmp_decomp/macos_class_gap_map.csv",
        help="Output gap map CSV path.",
    )
    ap.add_argument(
        "--raw-vtable-candidates-csv",
        default="tmp_decomp/macos_vtable_rename_candidates.csv",
        help="Raw vtable candidates CSV path.",
    )
    ap.add_argument(
        "--windows-slot-writes-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_writes.csv",
        help="Raw runtime slot writes CSV path.",
    )
    ap.add_argument(
        "--windows-slot-map-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_map.csv",
        help="Best runtime class/slot map CSV path.",
    )
    ap.add_argument(
        "--renames-csv",
        default="tmp_decomp/macos_vocab_wave_renames.csv",
        help="Wave rename CSV path.",
    )
    ap.add_argument(
        "--signatures-csv",
        default="tmp_decomp/macos_vocab_wave_signatures.csv",
        help="Wave signatures CSV path.",
    )
    ap.add_argument(
        "--macos-csv",
        default="tmp_decomp/macos_class_methods.csv",
        help="macOS class methods CSV path.",
    )
    ap.add_argument(
        "--macos-vtable-layout-csv",
        default="tmp_decomp/macos_vtable_layout.csv",
        help="macOS vtable layout CSV path.",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Optional comma-separated class filter.",
    )
    ap.add_argument(
        "--top-classes",
        type=int,
        default=20,
        help="Top-N ranked classes to include (default: 20).",
    )
    ap.add_argument(
        "--actionable-only",
        action="store_true",
        help="Restrict gap map to classes with generic methods already in class namespace.",
    )
    ap.add_argument(
        "--max-per-class",
        type=int,
        default=6,
        help="Max rename rows per class (default: 6).",
    )
    ap.add_argument(
        "--confidence-filter",
        choices=["high", "medium", "low"],
        default="high",
        help="Minimum confidence threshold (default: high).",
    )
    ap.add_argument(
        "--allow-overwrite-named",
        action="store_true",
        help="Allow renaming non-generic currently named functions.",
    )
    ap.add_argument(
        "--emit-thiscall-signatures",
        action="store_true",
        help="Generate thiscall signature hints (default: off).",
    )
    ap.add_argument("--auto-thunk-mirrors", action="store_true")
    ap.add_argument("--emit-detail-artifacts", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    py = sys.executable
    base = [py, "-m", "imperialism_re.cli"]

    gap_map_csv = Path(args.gap_map_csv)
    if not gap_map_csv.is_absolute():
        gap_map_csv = root / gap_map_csv
    raw_vtable_csv = Path(args.raw_vtable_candidates_csv)
    if not raw_vtable_csv.is_absolute():
        raw_vtable_csv = root / raw_vtable_csv
    windows_slot_writes_csv = Path(args.windows_slot_writes_csv)
    if not windows_slot_writes_csv.is_absolute():
        windows_slot_writes_csv = root / windows_slot_writes_csv
    windows_slot_map_csv = Path(args.windows_slot_map_csv)
    if not windows_slot_map_csv.is_absolute():
        windows_slot_map_csv = root / windows_slot_map_csv
    renames_csv = Path(args.renames_csv)
    if not renames_csv.is_absolute():
        renames_csv = root / renames_csv
    signatures_csv = Path(args.signatures_csv)
    if not signatures_csv.is_absolute():
        signatures_csv = root / signatures_csv

    # 1) Gap map
    cmd_gap = base + [
        "build_macos_class_gap_map",
        "--project-root",
        str(root),
        "--macos-csv",
        str(args.macos_csv),
        "--out-csv",
        str(gap_map_csv),
        "--top-classes",
        str(args.top_classes),
    ]
    if args.actionable_only:
        cmd_gap.append("--actionable-only")
    if args.classes:
        cmd_gap.extend(["--classes", args.classes])
    rc = _run(cmd_gap)
    if rc != 0:
        return rc

    gap_rows = _read_rows(gap_map_csv)
    classes = _select_classes_from_gap(gap_rows, args.top_classes)
    if not classes:
        print("[done] no actionable classes from gap map; nothing to apply")
        return 0

    classes_csv = ",".join(classes)

    # 2) Build runtime slot map from write paths
    cmd_runtime_slot = base + [
        "extract_windows_runtime_vtable_slot_writes",
        "--project-root",
        str(root),
        "--out-csv",
        str(windows_slot_writes_csv),
        "--out-best-csv",
        str(windows_slot_map_csv),
        "--classes",
        classes_csv,
    ]
    rc = _run(cmd_runtime_slot)
    if rc != 0:
        return rc

    # 3) Infer vtable candidates
    cmd_infer = base + [
        "infer_name_from_macos_vtable",
        "--project-root",
        str(root),
        "--vtable-layout-csv",
        str(args.macos_vtable_layout_csv),
        "--windows-slot-map-csv",
        str(windows_slot_map_csv),
        "--out-csv",
        str(raw_vtable_csv),
        "--confidence-filter",
        "all",
        "--classes",
        classes_csv,
    ]
    rc = _run(cmd_infer)
    if rc != 0:
        return rc

    # 4) Generate wave CSVs
    cmd_gen = base + [
        "generate_macos_vocab_candidates",
        "--project-root",
        str(root),
        "--gap-map-csv",
        str(gap_map_csv),
        "--vtable-candidates-csv",
        str(raw_vtable_csv),
        "--out-renames-csv",
        str(renames_csv),
        "--out-signatures-csv",
        str(signatures_csv),
        "--classes",
        classes_csv,
        "--top-classes",
        str(args.top_classes),
        "--confidence-filter",
        args.confidence_filter,
        "--max-per-class",
        str(args.max_per_class),
    ]
    if args.allow_overwrite_named:
        cmd_gen.append("--allow-overwrite-named")
    if args.emit_thiscall_signatures:
        cmd_gen.append("--emit-thiscall-signatures")
    rc = _run(cmd_gen)
    if rc != 0:
        return rc

    rename_rows = _read_rows(renames_csv)
    if not rename_rows:
        print("[done] generated 0 rename rows; skipping run_wave_bundle")
        return 0

    signature_rows = _read_rows(signatures_csv)

    # 5) Apply wave bundle
    cmd_wave = base + [
        "run_wave_bundle",
        "--project-root",
        str(root),
        "--batch-tag",
        args.batch_tag,
        "--renames-csv",
        str(renames_csv),
    ]
    if signature_rows:
        cmd_wave.extend(["--signatures-csv", str(signatures_csv)])
    if args.auto_thunk_mirrors:
        cmd_wave.append("--auto-thunk-mirrors")
    if args.emit_detail_artifacts:
        cmd_wave.append("--emit-detail-artifacts")
    if args.apply:
        cmd_wave.append("--apply")
    rc = _run(cmd_wave)
    if rc != 0:
        return rc

    print(
        f"[done] macos_vocab_wave batch={args.batch_tag} "
        f"rename_rows={len(rename_rows)} signature_rows={len(signature_rows)} apply={int(args.apply)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
