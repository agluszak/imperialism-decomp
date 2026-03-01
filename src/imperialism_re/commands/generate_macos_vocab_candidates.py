#!/usr/bin/env python3
"""
Generate conservative, wave-ready rename candidates from macOS vtable hints.

Inputs:
  - macOS class gap map (`build_macos_class_gap_map`)
  - raw vtable rename candidates (`infer_name_from_macos_vtable`)

Outputs:
  - rename CSV compatible with `apply_function_renames_csv` / `run_wave_bundle`
  - signature CSV compatible with `apply_signatures_from_csv` (optionally empty)
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import load_csv_rows, write_csv_rows
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.wave_shared import is_unresolved_name


CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


def _parse_class_filter(raw: str) -> set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


def _confidence_allows(row_conf: str, threshold: str) -> bool:
    row_rank = CONFIDENCE_ORDER.get((row_conf or "").strip().lower(), 0)
    threshold_rank = CONFIDENCE_ORDER.get((threshold or "").strip().lower(), 0)
    return row_rank >= threshold_rank


def _is_generic_name(name: str) -> bool:
    if is_unresolved_name(name):
        return True
    if name.startswith("thunk_"):
        return True
    if name.startswith("CreateSingleJmpThunk_"):
        return True
    if name.startswith("WrapperFor_Cluster_"):
        return True
    if name.startswith("OrphanCallChain_"):
        return True
    if "_VtblSlot" in name:
        return True
    return False


def _pick_gap_classes(
    gap_rows: list[dict[str, str]],
    class_filter: set[str],
    top_classes: int,
) -> list[str]:
    rank_map: dict[str, int] = {}
    for row in gap_rows:
        class_name = (row.get("class_name") or "").strip()
        if not class_name:
            continue
        if class_filter and class_name not in class_filter:
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
    ap = argparse.ArgumentParser(
        description="Build conservative macOS-vocabulary rename/signature candidate CSVs.",
    )
    ap.add_argument(
        "--gap-map-csv",
        default="tmp_decomp/macos_class_gap_map.csv",
        help="Gap map CSV from build_macos_class_gap_map.",
    )
    ap.add_argument(
        "--vtable-candidates-csv",
        default="tmp_decomp/macos_vtable_rename_candidates.csv",
        help="Raw vtable candidates CSV from infer_name_from_macos_vtable.",
    )
    ap.add_argument(
        "--out-renames-csv",
        default="tmp_decomp/macos_vocab_wave_renames.csv",
        help="Output rename CSV (wave-ready).",
    )
    ap.add_argument(
        "--out-signatures-csv",
        default="tmp_decomp/macos_vocab_wave_signatures.csv",
        help="Output signatures CSV (wave-ready; may be empty).",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Optional comma-separated class filter.",
    )
    ap.add_argument(
        "--top-classes",
        type=int,
        default=0,
        help="Restrict to top-N classes by gap-map rank (0 = all in filter).",
    )
    ap.add_argument(
        "--confidence-filter",
        choices=["high", "medium", "low"],
        default="high",
        help="Minimum confidence from vtable candidates (default: high).",
    )
    ap.add_argument(
        "--max-per-class",
        type=int,
        default=0,
        help="Max rename rows per class (0 = no limit).",
    )
    ap.add_argument(
        "--allow-overwrite-named",
        action="store_true",
        help="Allow renaming non-generic currently named functions.",
    )
    ap.add_argument(
        "--allow-duplicate-proposed-name",
        action="store_true",
        help="Allow duplicate proposed method names within a class.",
    )
    ap.add_argument(
        "--emit-thiscall-signatures",
        action="store_true",
        help="Emit __thiscall signature hints with current return type (conservative no-param rewrite).",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    gap_map_csv = Path(args.gap_map_csv)
    if not gap_map_csv.is_absolute():
        gap_map_csv = root / gap_map_csv
    if not gap_map_csv.exists():
        print(f"[error] missing gap map CSV: {gap_map_csv}")
        return 1

    vtable_candidates_csv = Path(args.vtable_candidates_csv)
    if not vtable_candidates_csv.is_absolute():
        vtable_candidates_csv = root / vtable_candidates_csv
    if not vtable_candidates_csv.exists():
        print(f"[error] missing vtable candidates CSV: {vtable_candidates_csv}")
        return 1

    out_renames_csv = Path(args.out_renames_csv)
    if not out_renames_csv.is_absolute():
        out_renames_csv = root / out_renames_csv
    out_renames_csv.parent.mkdir(parents=True, exist_ok=True)

    out_signatures_csv = Path(args.out_signatures_csv)
    if not out_signatures_csv.is_absolute():
        out_signatures_csv = root / out_signatures_csv
    out_signatures_csv.parent.mkdir(parents=True, exist_ok=True)

    class_filter = _parse_class_filter(args.classes)
    gap_rows = load_csv_rows(gap_map_csv)
    target_classes = set(_pick_gap_classes(gap_rows, class_filter, args.top_classes))
    if not target_classes:
        print("[warn] no target classes selected from gap map")
        write_csv_rows(out_renames_csv, [], ["address", "new_name", "comment"])
        write_csv_rows(
            out_signatures_csv,
            [],
            ["address", "calling_convention", "return_type", "params"],
        )
        return 0

    candidates = load_csv_rows(vtable_candidates_csv)

    by_class: dict[str, list[dict[str, str]]] = defaultdict(list)
    candidates_by_address: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in candidates:
        class_name = (row.get("class_name") or "").strip()
        if class_name not in target_classes:
            continue
        confidence = (row.get("confidence") or "").strip().lower()
        if not _confidence_allows(confidence, args.confidence_filter):
            continue
        current_name = (row.get("current_name") or "").strip()
        if not args.allow_overwrite_named and not _is_generic_name(current_name):
            continue
        address = (row.get("address") or "").strip().lower()
        if not address:
            continue
        by_class[class_name].append(row)
        candidates_by_address[address].append(row)

    rename_rows: list[dict[str, str]] = []
    signature_rows: list[dict[str, str]] = []
    skipped_duplicate_name = 0
    skipped_max_per_class = 0
    skipped_bad_address = 0
    skipped_ambiguous_address = 0

    for class_name in sorted(by_class):
        rows = by_class[class_name]
        rows.sort(
            key=lambda r: (
                -CONFIDENCE_ORDER.get((r.get("confidence") or "").strip().lower(), 0),
                int((r.get("slot_index") or "999999").strip() or "999999"),
                (r.get("address") or "").strip(),
            )
        )
        used_names: set[str] = set()
        emitted = 0
        for row in rows:
            address = (row.get("address") or "").strip()
            proposed = (row.get("proposed_name") or "").strip()
            confidence = (row.get("confidence") or "").strip().lower()
            slot = (row.get("slot_index") or "").strip()
            current_name = (row.get("current_name") or "").strip()
            if not address or not proposed:
                continue
            try:
                int(address, 16)
            except ValueError:
                skipped_bad_address += 1
                continue
            address_key = address.lower()
            addr_rows = candidates_by_address.get(address_key, [])
            if len(addr_rows) > 1:
                unique_pairs = {(r.get("class_name") or "", r.get("proposed_name") or "") for r in addr_rows}
                if len(unique_pairs) > 1:
                    skipped_ambiguous_address += 1
                    continue
            if not args.allow_duplicate_proposed_name and proposed in used_names:
                skipped_duplicate_name += 1
                continue
            if args.max_per_class > 0 and emitted >= args.max_per_class:
                skipped_max_per_class += 1
                continue

            comment = (
                f"macos_vtable_slot={slot};class={class_name};confidence={confidence};"
                f"current={current_name}"
            )
            rename_rows.append(
                {
                    "address": address,
                    "new_name": proposed,
                    "comment": comment,
                }
            )
            used_names.add(proposed)
            emitted += 1

    if args.emit_thiscall_signatures and rename_rows:
        return_type_by_addr: dict[str, str] = {}
        with open_program(root) as program:
            fm = program.getFunctionManager()
            af = program.getAddressFactory().getDefaultAddressSpace()
            for row in rename_rows:
                address = row["address"]
                try:
                    addr_int = int(address, 16)
                except ValueError:
                    continue
                fn = fm.getFunctionAt(af.getAddress(f"{addr_int:08x}"))
                if fn is None:
                    continue
                ret_dt = fn.getReturnType()
                ret_name = "int" if ret_dt is None else str(ret_dt.getName())
                return_type_by_addr[address] = ret_name

        for row in rename_rows:
            address = row["address"]
            signature_rows.append(
                {
                    "address": address,
                    "calling_convention": "__thiscall",
                    "return_type": return_type_by_addr.get(address, "int"),
                    "params": "",
                }
            )

    write_csv_rows(out_renames_csv, rename_rows, ["address", "new_name", "comment"])
    write_csv_rows(
        out_signatures_csv,
        signature_rows,
        ["address", "calling_convention", "return_type", "params"],
    )

    classes_with_rows = len({row["comment"].split("class=", 1)[1].split(";", 1)[0] for row in rename_rows})
    print(
        f"[saved] {out_renames_csv} rows={len(rename_rows)} classes={classes_with_rows} "
        f"filter={args.confidence_filter}"
    )
    print(f"[saved] {out_signatures_csv} rows={len(signature_rows)}")
    print(
        "[stats] "
        f"skipped_duplicate_name={skipped_duplicate_name} "
        f"skipped_max_per_class={skipped_max_per_class} "
        f"skipped_bad_address={skipped_bad_address} "
        f"skipped_ambiguous_address={skipped_ambiguous_address}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
