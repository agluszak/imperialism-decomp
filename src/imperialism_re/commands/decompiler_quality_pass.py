#!/usr/bin/env python3
"""
Re-decompile functions with quality-configured settings and report metrics.

Decompiles each function twice — once with default settings (matching existing
command behavior) and once with ``create_configured_decompiler`` quality knobs —
then reports success rate and output-size deltas in a CSV.

Usage:
  uv run impk decompiler_quality_pass --out-csv tmp_decomp/decomp_quality.csv
  uv run impk decompiler_quality_pass --max-functions 20 --out-csv tmp_decomp/quality_test.csv
  uv run impk decompiler_quality_pass --namespace TradeControl --out-csv tmp_decomp/quality_tc.csv
  uv run impk decompiler_quality_pass --only-class-methods --max-functions 50 --out-csv tmp_decomp/quality_cls.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.decompiler import (
    create_configured_decompiler,
    decompile_function_text,
)
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Re-decompile functions with quality settings and report metrics.",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-functions", type=int, default=0, help="Limit functions to process (0=all)")
    ap.add_argument("--namespace", default="", help="Limit to functions in this namespace")
    ap.add_argument("--only-class-methods", action="store_true", help="Only decompile class-namespaced methods")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with open_program(root) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        # Build filter sets
        class_namespaces: set[str] = set()
        if args.only_class_methods:
            it_cls = st.getClassNamespaces()
            while it_cls.hasNext():
                class_namespaces.add(it_cls.next().getName())

        # Default decompiler (no quality options)
        ifc_default = DecompInterface()
        ifc_default.openProgram(program)

        # Quality decompiler
        ifc_quality = create_configured_decompiler(program)

        rows = []
        processed = 0
        default_fail = 0
        quality_fail = 0
        improved = 0

        fit = fm.getFunctions(True)
        while fit.hasNext():
            if args.max_functions and processed >= args.max_functions:
                break

            func = fit.next()
            ns = func.getParentNamespace()
            ns_name = ns.getName() if ns != global_ns else ""

            # Namespace filter
            if args.namespace and ns_name != args.namespace:
                continue

            # Class-only filter
            if args.only_class_methods:
                if ns_name not in class_namespaces:
                    continue

            processed += 1
            addr = f"0x{func.getEntryPoint().getOffset():08x}"
            fn_name = func.getName()

            text_default = decompile_function_text(ifc_default, func)
            text_quality = decompile_function_text(ifc_quality, func)

            d_ok = len(text_default) > 0
            q_ok = len(text_quality) > 0
            size_d = len(text_default)
            size_q = len(text_quality)
            delta = size_q - size_d

            if not d_ok:
                default_fail += 1
            if not q_ok:
                quality_fail += 1
            if delta > 0:
                improved += 1

            rows.append({
                "address": addr,
                "name": fn_name,
                "namespace": ns_name,
                "default_ok": d_ok,
                "quality_ok": q_ok,
                "size_default": size_d,
                "size_quality": size_q,
                "size_delta": delta,
            })

            if processed % 200 == 0:
                print(f"  [{processed}] {fn_name} default={size_d} quality={size_q} delta={delta:+d}")

        ifc_default.dispose()
        ifc_quality.dispose()

    # Write CSV
    fieldnames = [
        "address", "name", "namespace", "default_ok", "quality_ok",
        "size_default", "size_quality", "size_delta",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"\n[done] processed={processed} default_fail={default_fail} quality_fail={quality_fail} improved={improved}")
    print(f"[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
