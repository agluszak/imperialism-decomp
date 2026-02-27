#!/usr/bin/env python3
"""
Apply enum datatypes to struct fields from candidate CSV using direct+cluster thresholds.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.enum_candidates import (
    aggregate_struct_field_candidates,
    load_candidate_rows,
    parse_domains_filter,
)
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--domains", default="", help="Optional comma-separated domain filter")
    ap.add_argument("--min-evidence", type=int, default=3)
    ap.add_argument("--cluster-threshold", type=int, default=1)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing in-csv: {in_csv}")
        return 1

    rows = load_candidate_rows(in_csv)
    plans = aggregate_struct_field_candidates(
        rows,
        domains_filter=parse_domains_filter(args.domains),
        min_evidence=args.min_evidence,
        cluster_threshold=args.cluster_threshold,
    )

    print(
        f"[plan] candidates={len(plans)} min_evidence={args.min_evidence} "
        f"cluster_threshold={args.cluster_threshold} apply={int(args.apply)}"
    )

    with open_program(root) as program:
        from ghidra.program.model.data import DataTypeConflictHandler, Structure

        dtm = program.getDataTypeManager()

        resolved = []
        for p in plans:
            struct_path = str(p["struct_path"])
            off = int(p["offset"])
            enum_path = str(p["enum_path"])
            st = dtm.getDataType(struct_path)
            if st is None:
                print(f"[skip] {struct_path}+0x{off:x} missing struct")
                continue
            if not isinstance(st, Structure):
                print(f"[skip] {struct_path}+0x{off:x} not a structure")
                continue
            enum_dt = resolve_datatype_by_path_or_legacy_aliases(dtm, enum_path)
            if enum_dt is None:
                print(f"[skip] {struct_path}+0x{off:x} missing enum {enum_path}")
                continue
            resolved.append((st, struct_path, off, enum_dt, p))

        for _st, struct_path, off, enum_dt, p in resolved[:200]:
            print(
                f"  {struct_path}+0x{off:x} -> {enum_dt.getPathName()} "
                f"domain={p['domain']}"
            )
        if len(resolved) > 200:
            print(f"... ({len(resolved)-200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply enum struct field types from clustered candidates")
        ok = skip = fail = 0
        try:
            for st, struct_path, off, enum_dt, p in resolved:
                try:
                    st_copy = st.copy(dtm)
                    comp = st_copy.getComponentContaining(off)
                    if comp is None or comp.getOffset() != off:
                        skip += 1
                        print(f"[skip] {struct_path}+0x{off:x} no exact component")
                        continue
                    cur_dt = comp.getDataType()
                    if str(cur_dt.getPathName()) == str(enum_dt.getPathName()):
                        skip += 1
                        continue
                    fname = (p.get("field_name") or "").strip() or comp.getFieldName()
                    if not fname:
                        fname = f"field_{off:x}"
                    st_copy.replaceAtOffset(off, enum_dt, enum_dt.getLength(), fname, comp.getComment())
                    dtm.addDataType(st_copy, DataTypeConflictHandler.REPLACE_HANDLER)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {struct_path}+0x{off:x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply enum struct field types clustered", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
