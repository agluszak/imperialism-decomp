#!/usr/bin/env python3
"""
Build reusable CSV plans from Windows vtable slot map:
  1) global vtable-base label plan (for apply_global_data_from_csv)
  2) class-attach/rename plan (for attach_functions_to_class_csv)

Inputs:
  - windows runtime vtable slot map CSV (best rows):
      class_name,slot_index,vtable_base_addr,target_addr,target_name,confidence,...

Outputs:
  - labels CSV columns: address,new_name,type,comment
  - attach CSV columns: address,class_name,new_name,reason
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.wave_shared import is_unresolved_name


CONF_RANK = {"low": 1, "medium": 2, "high": 3}


def _confidence_allows(value: str, threshold: str) -> bool:
    return CONF_RANK.get((value or "").strip().lower(), 0) >= CONF_RANK.get(
        (threshold or "").strip().lower(),
        0,
    )


def _sanitize_ident(text: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_]", "_", text.strip())
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        return "UnknownClass"
    if out[0].isdigit():
        out = f"_{out}"
    return out


def _is_generic_name(name: str) -> bool:
    n = (name or "").strip()
    if not n:
        return True
    if is_unresolved_name(n):
        return True
    if n.startswith("thunk_"):
        return True
    if n.startswith("OrphanCallChain_"):
        return True
    if n.startswith("CreateSingleJmpThunk_"):
        return True
    if n.startswith("WrapperFor_"):
        return True
    if n.startswith("Cluster_"):
        return True
    if "_VtblSlot" in n:
        return True
    if re.match(r"^[A-Za-z0-9_]+_Slot\d+_Target$", n):
        return True
    return False


def _choose_base_label_class(class_names: list[str]) -> str:
    def score(name: str) -> tuple[int, int, str]:
        s = 0
        if name.startswith("T"):
            s += 30
        elif name.startswith("C"):
            s += 20
        elif name.startswith("Frog"):
            s += 10
        if "FID_" in name:
            s -= 8
        if name.startswith("Family_"):
            s -= 12
        if name.startswith("Candidate_"):
            s -= 100
        return (s, -len(name), name)

    return sorted(class_names, key=score, reverse=True)[0]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build vtable base-label and class-attach plans from windows slot map.",
    )
    ap.add_argument(
        "--slot-map-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_map_all.csv",
        help="Input slot map CSV.",
    )
    ap.add_argument(
        "--out-labels-csv",
        default="tmp_decomp/windows_vtable_base_labels_apply.csv",
        help="Output labels CSV for apply_global_data_from_csv.",
    )
    ap.add_argument(
        "--out-attach-csv",
        default="tmp_decomp/windows_vtable_slot_attach_apply.csv",
        help="Output attach CSV for attach_functions_to_class_csv.",
    )
    ap.add_argument(
        "--confidence-filter",
        choices=["low", "medium", "high"],
        default="high",
        help="Minimum slot confidence accepted (default: high).",
    )
    ap.add_argument(
        "--exclude-class-prefixes",
        default="Candidate_",
        help="Comma-separated class-name prefixes to exclude.",
    )
    ap.add_argument(
        "--only-existing-class-namespaces",
        action="store_true",
        help="Only emit attach rows for classes that already exist as namespaces.",
    )
    ap.add_argument(
        "--rename-generic-slot-methods",
        action="store_true",
        help="Emit class slot rename (<Class>_VtblSlotNNN) for generic target names.",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    slot_map_csv = Path(args.slot_map_csv)
    if not slot_map_csv.is_absolute():
        slot_map_csv = root / slot_map_csv
    out_labels_csv = Path(args.out_labels_csv)
    if not out_labels_csv.is_absolute():
        out_labels_csv = root / out_labels_csv
    out_labels_csv.parent.mkdir(parents=True, exist_ok=True)
    out_attach_csv = Path(args.out_attach_csv)
    if not out_attach_csv.is_absolute():
        out_attach_csv = root / out_attach_csv
    out_attach_csv.parent.mkdir(parents=True, exist_ok=True)

    excluded_prefixes = tuple(
        p.strip() for p in (args.exclude_class_prefixes or "").split(",") if p.strip()
    )

    raw_rows: list[dict[str, str]] = []
    with slot_map_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            cls = (row.get("class_name") or "").strip()
            if not cls:
                continue
            if excluded_prefixes and cls.startswith(excluded_prefixes):
                continue
            conf = (row.get("confidence") or "").strip().lower()
            if not _confidence_allows(conf, args.confidence_filter):
                continue
            raw_rows.append(row)

    if not raw_rows:
        write_csv_rows(out_labels_csv, [], ["address", "new_name", "type", "comment"])
        write_csv_rows(out_attach_csv, [], ["address", "class_name", "new_name", "reason"])
        print("[done] no filtered rows")
        return 0

    existing_classes: set[str] = set()
    current_name_by_addr: dict[str, str] = {}
    with open_program(root) as program:
        st = program.getSymbolTable()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            existing_classes.add(it_cls.next().getName())

        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        addrs = {((r.get("target_addr") or "").strip().lower()) for r in raw_rows}
        for a in sorted(addrs):
            if not a:
                continue
            try:
                ai = int(a, 16)
            except ValueError:
                continue
            fn = fm.getFunctionAt(af.getAddress(f"0x{ai:08x}"))
            if fn is not None:
                current_name_by_addr[a] = str(fn.getName())

    # 1) Build vtable base label rows.
    class_by_base: dict[str, list[str]] = defaultdict(list)
    for r in raw_rows:
        cls = (r.get("class_name") or "").strip()
        base = (r.get("vtable_base_addr") or "").strip().lower()
        if not cls or not base:
            continue
        class_by_base[base].append(cls)

    label_rows: list[dict[str, str]] = []
    duplicate_base_count = 0
    for base, classes in sorted(class_by_base.items()):
        uniq_classes = sorted(set(classes))
        if len(uniq_classes) > 1:
            duplicate_base_count += 1
        chosen = _choose_base_label_class(uniq_classes)
        chosen_id = _sanitize_ident(chosen)
        comment = ""
        aliases = [c for c in uniq_classes if c != chosen]
        if aliases:
            comment = "aliases=" + ",".join(aliases[:6])
        label_rows.append(
            {
                "address": base,
                "new_name": f"g_vtbl{chosen_id}",
                "type": "",
                "comment": comment,
            }
        )

    # 2) Build class attach rows, skipping ambiguous address->class mappings.
    rows_by_target_addr: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in raw_rows:
        target_addr = (r.get("target_addr") or "").strip().lower()
        if target_addr:
            rows_by_target_addr[target_addr].append(r)

    attach_rows: list[dict[str, str]] = []
    skipped_ambiguous = 0
    skipped_missing_ns = 0
    renamed_generic = 0

    for target_addr, rows in sorted(rows_by_target_addr.items()):
        classes = sorted({(r.get("class_name") or "").strip() for r in rows if r.get("class_name")})
        if len(classes) != 1:
            skipped_ambiguous += 1
            continue
        cls = classes[0]
        if args.only_existing_class_namespaces and cls not in existing_classes:
            skipped_missing_ns += 1
            continue

        rows_same_class = [r for r in rows if (r.get("class_name") or "").strip() == cls]
        rows_same_class.sort(key=lambda r: int((r.get("slot_index") or "999999").strip() or "999999"))
        chosen = rows_same_class[0]
        slot = int((chosen.get("slot_index") or "0").strip() or "0")
        base_addr = (chosen.get("vtable_base_addr") or "").strip().lower()
        current_name = current_name_by_addr.get(target_addr, (chosen.get("target_name") or "").strip())
        new_name = ""
        if args.rename_generic_slot_methods and _is_generic_name(current_name):
            # Rename only when this address appears at a single slot for this class.
            uniq_slots = {int((r.get("slot_index") or "0").strip() or "0") for r in rows_same_class}
            if len(uniq_slots) == 1:
                cls_id = _sanitize_ident(cls)
                new_name = f"{cls_id}_VtblSlot{slot:03d}"
                renamed_generic += 1

        reason = f"slot={slot};base={base_addr};confidence={chosen.get('confidence','')}"
        attach_rows.append(
            {
                "address": target_addr,
                "class_name": cls,
                "new_name": new_name,
                "reason": reason,
            }
        )

    write_csv_rows(out_labels_csv, label_rows, ["address", "new_name", "type", "comment"])
    write_csv_rows(out_attach_csv, attach_rows, ["address", "class_name", "new_name", "reason"])

    print(
        f"[saved] {out_labels_csv} rows={len(label_rows)} "
        f"bases_with_aliases={duplicate_base_count}"
    )
    print(
        f"[saved] {out_attach_csv} rows={len(attach_rows)} "
        f"renamed_generic={renamed_generic}"
    )
    print(
        "[stats] "
        f"filtered_rows={len(raw_rows)} "
        f"skipped_ambiguous_target_addr={skipped_ambiguous} "
        f"skipped_missing_namespace={skipped_missing_ns} "
        f"existing_class_namespaces={len(existing_classes)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
