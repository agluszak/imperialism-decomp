#!/usr/bin/env python3
"""
Ensure missing class namespaces from Windows vtable slot-map evidence.

This command is intentionally conservative:
  - consumes a slot-map CSV
  - applies confidence and class-name filters
  - requires a minimum evidence row count per class
  - emits a plan CSV and (optionally) creates missing class namespaces
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program


CONF_RANK = {"low": 1, "medium": 2, "high": 3}


def _confidence_allows(value: str, threshold: str) -> bool:
    return CONF_RANK.get((value or "").strip().lower(), 0) >= CONF_RANK.get(
        (threshold or "").strip().lower(),
        0,
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Create missing class namespaces from vtable slot-map evidence.",
    )
    ap.add_argument(
        "--slot-map-csv",
        default="tmp_decomp/windows_runtime_vtable_slot_map_all.csv",
        help="Input slot-map CSV.",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/windows_missing_class_namespace_plan.csv",
        help="Output plan CSV.",
    )
    ap.add_argument(
        "--confidence-filter",
        choices=["low", "medium", "high"],
        default="high",
        help="Minimum evidence confidence (default: high).",
    )
    ap.add_argument(
        "--min-rows-per-class",
        type=int,
        default=8,
        help="Minimum slot rows required to consider a class (default: 8).",
    )
    ap.add_argument(
        "--exclude-class-prefixes",
        default="Candidate_,CHeaderCtrl_FID_,CListBox_FID_,NationInteractionMgr_slot",
        help="Comma-separated class prefixes to exclude.",
    )
    ap.add_argument(
        "--exclude-class-regex",
        default=r".*_slot[0-9A-Fa-f]+$",
        help="Optional regex to exclude class names (default: .*_slot[0-9A-Fa-f]+$).",
    )
    ap.add_argument("--apply", action="store_true", help="Create namespaces")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    slot_map_csv = Path(args.slot_map_csv)
    if not slot_map_csv.is_absolute():
        slot_map_csv = root / slot_map_csv
    if not slot_map_csv.exists():
        print(f"[error] missing slot map csv: {slot_map_csv}")
        return 1

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    excluded_prefixes = tuple(
        p.strip() for p in (args.exclude_class_prefixes or "").split(",") if p.strip()
    )
    excluded_re = re.compile(args.exclude_class_regex) if (args.exclude_class_regex or "").strip() else None

    rows: list[dict[str, str]] = []
    with slot_map_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            cls = (row.get("class_name") or "").strip()
            if not cls:
                continue
            if excluded_prefixes and cls.startswith(excluded_prefixes):
                continue
            if excluded_re is not None and excluded_re.match(cls):
                continue
            if not _confidence_allows((row.get("confidence") or "").strip(), args.confidence_filter):
                continue
            rows.append(row)

    by_class = Counter((r.get("class_name") or "").strip() for r in rows)
    by_class = Counter({k: v for k, v in by_class.items() if k and v >= args.min_rows_per_class})

    with open_program(root) as program:
        st = program.getSymbolTable()
        existing_classes: set[str] = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            existing_classes.add(it_cls.next().getName())

        plan_rows: list[dict[str, str]] = []
        for cls, count in sorted(by_class.items(), key=lambda kv: (-kv[1], kv[0])):
            class_rows = [r for r in rows if (r.get("class_name") or "").strip() == cls]
            base = ""
            for r in class_rows:
                base = (r.get("vtable_base_addr") or "").strip()
                if base:
                    break
            plan_rows.append(
                {
                    "class_name": cls,
                    "row_count": str(count),
                    "vtable_base_addr": base,
                    "already_exists": "1" if cls in existing_classes else "0",
                }
            )

        write_csv_rows(
            out_csv,
            plan_rows,
            ["class_name", "row_count", "vtable_base_addr", "already_exists"],
        )

        missing = [r for r in plan_rows if r["already_exists"] == "0"]
        print(
            f"[saved] {out_csv} rows={len(plan_rows)} "
            f"missing={len(missing)} existing={len(plan_rows)-len(missing)}"
        )
        if not args.apply:
            print("[dry-run] pass --apply to create missing class namespaces")
            return 0

        from ghidra.program.model.symbol import SourceType

        tx = program.startTransaction("Ensure class namespaces from slot map")
        ok = skip = fail = 0
        try:
            global_ns = program.getGlobalNamespace()
            for row in missing:
                cls = row["class_name"]
                try:
                    st.createClass(global_ns, cls, SourceType.USER_DEFINED)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] class={cls} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("ensure class namespaces from slot map", None)
        print(f"[done] created={ok} skipped={skip} failed={fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
