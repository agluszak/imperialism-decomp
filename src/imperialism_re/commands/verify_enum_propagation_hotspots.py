#!/usr/bin/env python3
"""
Verify enum propagation by checking candidate targets that are still untyped.

Emits only hotspot rows by default.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.enum_candidates import (
    aggregate_param_candidates,
    aggregate_struct_field_candidates,
    load_candidate_rows,
    parse_domains_filter,
)
from imperialism_re.core.ghidra_session import open_program


def _dtype_matches_enum(dt, enum_dt) -> bool:
    try:
        if str(dt.getPathName()) == str(enum_dt.getPathName()):
            return True
    except Exception:
        pass
    return str(dt.getName()) == str(enum_dt.getName())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--domains", default="", help="Optional comma-separated domain filter")
    ap.add_argument("--min-evidence", type=int, default=3)
    ap.add_argument("--cluster-threshold", type=int, default=1)
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing in-csv: {in_csv}")
        return 1

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows = load_candidate_rows(in_csv)
    domains_filter = parse_domains_filter(args.domains)

    param_plans = aggregate_param_candidates(
        rows,
        domains_filter=domains_filter,
        min_evidence=args.min_evidence,
        cluster_threshold=args.cluster_threshold,
    )
    struct_plans = aggregate_struct_field_candidates(
        rows,
        domains_filter=domains_filter,
        min_evidence=args.min_evidence,
        cluster_threshold=args.cluster_threshold,
    )

    hotspots: list[dict[str, str]] = []

    with open_program(root) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        for p in param_plans:
            faddr = int(p["function_addr"])
            pname = str(p["param_name"])
            enum_path = str(p["enum_path"])
            domain = str(p["domain"])
            fn = fm.getFunctionAt(af.getAddress(f"0x{faddr:08x}"))
            if fn is None:
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "param",
                        "target": f"0x{faddr:08x}",
                        "selector": pname,
                        "enum_path": enum_path,
                        "reason": "function_missing",
                        "current_type": "<missing>",
                    }
                )
                continue

            enum_dt = resolve_datatype_by_path_or_legacy_aliases(dtm, enum_path)
            if enum_dt is None:
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "param",
                        "target": f"0x{faddr:08x}:{fn.getName()}",
                        "selector": pname,
                        "enum_path": enum_path,
                        "reason": "enum_missing",
                        "current_type": "<missing_enum>",
                    }
                )
                continue

            params = list(fn.getParameters())
            idx = -1
            for i, par in enumerate(params):
                if (par.getName() or "").strip().lower() == pname.lower():
                    idx = i
                    break
            if idx < 0:
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "param",
                        "target": f"0x{faddr:08x}:{fn.getName()}",
                        "selector": pname,
                        "enum_path": enum_path,
                        "reason": "param_missing",
                        "current_type": "<missing_param>",
                    }
                )
                continue

            cur_dt = params[idx].getDataType()
            if not _dtype_matches_enum(cur_dt, enum_dt):
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "param",
                        "target": f"0x{faddr:08x}:{fn.getName()}",
                        "selector": pname,
                        "enum_path": enum_path,
                        "reason": "param_not_typed",
                        "current_type": str(cur_dt.getName()),
                    }
                )

        for p in struct_plans:
            struct_path = str(p["struct_path"])
            off = int(p["offset"])
            enum_path = str(p["enum_path"])
            domain = str(p["domain"])

            st = dtm.getDataType(struct_path)
            if st is None:
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "struct_field",
                        "target": struct_path,
                        "selector": f"0x{off:x}",
                        "enum_path": enum_path,
                        "reason": "struct_missing",
                        "current_type": "<missing_struct>",
                    }
                )
                continue

            enum_dt = resolve_datatype_by_path_or_legacy_aliases(dtm, enum_path)
            if enum_dt is None:
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "struct_field",
                        "target": struct_path,
                        "selector": f"0x{off:x}",
                        "enum_path": enum_path,
                        "reason": "enum_missing",
                        "current_type": "<missing_enum>",
                    }
                )
                continue

            comp = st.getComponentContaining(off)
            if comp is None or comp.getOffset() != off:
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "struct_field",
                        "target": struct_path,
                        "selector": f"0x{off:x}",
                        "enum_path": enum_path,
                        "reason": "field_missing",
                        "current_type": "<missing_field>",
                    }
                )
                continue

            cur_dt = comp.getDataType()
            if not _dtype_matches_enum(cur_dt, enum_dt):
                hotspots.append(
                    {
                        "domain": domain,
                        "kind": "struct_field",
                        "target": struct_path,
                        "selector": f"0x{off:x}",
                        "enum_path": enum_path,
                        "reason": "field_not_typed",
                        "current_type": str(cur_dt.getName()),
                    }
                )

    fieldnames = [
        "domain",
        "kind",
        "target",
        "selector",
        "enum_path",
        "reason",
        "current_type",
    ]
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=fieldnames)
        wr.writeheader()
        wr.writerows(hotspots)

    print(
        f"[saved] {out_csv} hotspots={len(hotspots)} "
        f"param_candidates={len(param_plans)} struct_candidates={len(struct_plans)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
