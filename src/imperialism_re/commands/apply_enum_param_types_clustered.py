#!/usr/bin/env python3
"""
Apply enum types to function parameters from candidate CSV using direct+cluster thresholds.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.enum_candidates import (
    aggregate_param_candidates,
    load_candidate_rows,
    parse_domains_filter,
)
from imperialism_re.core.ghidra_session import open_program


INTEGRAL_TYPES = {
    "byte",
    "char",
    "short",
    "ushort",
    "int",
    "uint",
    "long",
    "ulong",
    "undefined1",
    "undefined2",
    "undefined4",
}


def _is_integral_nonptr(dt_name: str) -> bool:
    t = dt_name.strip().replace(" ", "").lower()
    return "*" not in t and t in INTEGRAL_TYPES


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
    plans = aggregate_param_candidates(
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
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        resolved_plans = []
        for p in plans:
            faddr = int(p["function_addr"])
            pname = str(p["param_name"])
            epath = str(p["enum_path"])
            fn = fm.getFunctionAt(af.getAddress(f"0x{faddr:08x}"))
            if fn is None:
                continue
            enum_dt = resolve_datatype_by_path_or_legacy_aliases(dtm, epath)
            if enum_dt is None:
                print(f"[skip] 0x{faddr:08x} {fn.getName()} missing enum {epath}")
                continue

            params = list(fn.getParameters())
            idx = -1
            for i, par in enumerate(params):
                if (par.getName() or "").strip().lower() == pname.lower():
                    idx = i
                    break
            if idx < 0:
                print(f"[skip] 0x{faddr:08x} {fn.getName()} missing param {pname}")
                continue

            cur_name = str(params[idx].getDataType().getName() or "")
            if not _is_integral_nonptr(cur_name):
                print(
                    f"[skip] 0x{faddr:08x} {fn.getName()} {pname} current={cur_name} "
                    f"(not integral non-ptr)"
                )
                continue

            resolved_plans.append((fn, idx, pname, enum_dt, p))

        for fn, idx, pname, enum_dt, p in resolved_plans[:200]:
            print(
                f"  {fn.getEntryPoint()} {fn.getName()} param={pname} idx={idx} "
                f"-> {enum_dt.getPathName()} domain={p['domain']}"
            )
        if len(resolved_plans) > 200:
            print(f"... ({len(resolved_plans)-200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply enum param types from clustered candidates")
        ok = skip = fail = 0
        try:
            for fn, idx, _pname, enum_dt, _p in resolved_plans:
                try:
                    old_sig = str(fn.getSignature())
                    old_params = list(fn.getParameters())
                    new_params = []
                    for i, par in enumerate(old_params):
                        dt = enum_dt if i == idx else par.getDataType()
                        new_params.append(
                            ParameterImpl(
                                par.getName(),
                                dt,
                                program,
                                SourceType.USER_DEFINED,
                            )
                        )
                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    new_sig = str(fn.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {fn.getEntryPoint()} {fn.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply enum param types clustered", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
