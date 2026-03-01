#!/usr/bin/env python3
"""
Analyze BSim match results: coverage map, cross-validation spot-check, ambiguous wrapper detection.

Items produced:
  1. Coverage map: class namespace breakdown — demo coverage vs main-only
  2. Cross-validation: named main functions and their best demo match (sim >= threshold)
  3. Ambiguous wrappers: main functions matching 2+ demo functions at sim >= 0.99

Usage:
  uv run impk analyze_bsim_results --in-csv tmp_decomp/bsim_matches_v1.csv
  uv run impk analyze_bsim_results --in-csv tmp_decomp/bsim_matches_v1.csv \\
      --coverage-csv tmp_decomp/bsim_coverage.csv \\
      --spot-check-csv tmp_decomp/bsim_spot_check.csv \\
      --ambiguous-csv tmp_decomp/bsim_ambiguous.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Analyze BSim match results: coverage, spot-check, ambiguous wrappers.",
    )
    ap.add_argument("--in-csv", required=True, help="BSim matches CSV from query_bsim_matches")
    ap.add_argument("--coverage-csv", default=None, help="Output coverage map CSV")
    ap.add_argument("--spot-check-csv", default=None, help="Output spot-check CSV")
    ap.add_argument("--ambiguous-csv", default=None, help="Output ambiguous wrappers CSV")
    ap.add_argument(
        "--sim-spot-check",
        type=float,
        default=0.95,
        help="Min similarity for spot-check output (default: 0.95)",
    )
    ap.add_argument(
        "--sim-ambiguous",
        type=float,
        default=0.99,
        help="Min similarity for ambiguous wrapper detection (default: 0.99)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] CSV not found: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    print(f"[load] {len(rows)} rows from {in_csv}")

    # Build lookups: main_addr -> best row (highest sim) and all rows
    main_to_best: dict[int, dict] = {}
    main_to_all: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        addr = int(row["main_address"], 16)
        main_to_all[addr].append(row)
        sim = float(row["similarity"])
        if addr not in main_to_best or sim > float(main_to_best[addr]["similarity"]):
            main_to_best[addr] = row

    matched_addrs = set(main_to_best.keys())

    with open_program(root) as program:
        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()

        all_funcs = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            all_funcs.append(fit.next())

        print(f"[main] total functions: {len(all_funcs)}")
        print(f"[matches] unique matched main addresses: {len(matched_addrs)}")
        pct = len(matched_addrs) / len(all_funcs) * 100 if all_funcs else 0
        print(f"[coverage] overall: {len(matched_addrs)}/{len(all_funcs)} = {pct:.1f}%")

        # ---------------------------------------------------------------
        # Item 1: Coverage Map
        # ---------------------------------------------------------------
        print("\n" + "=" * 70)
        print("ITEM 1: COVERAGE MAP (functions present in demo vs main-only)")
        print("=" * 70)

        ns_total: Counter = Counter()
        ns_matched_07: Counter = Counter()
        ns_matched_09: Counter = Counter()
        unmatched_named: list[dict] = []

        for fn in all_funcs:
            addr = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            ns = fn.getParentNamespace()
            ns_name = ns.getName() if ns and ns != global_ns else "<global>"
            fn_name = fn.getName()

            ns_total[ns_name] += 1
            if addr in main_to_best:
                best_sim = float(main_to_best[addr]["similarity"])
                if best_sim >= 0.7:
                    ns_matched_07[ns_name] += 1
                if best_sim >= 0.9:
                    ns_matched_09[ns_name] += 1
            else:
                if not fn_name.startswith("FUN_") and not fn_name.startswith("thunk_FUN_"):
                    unmatched_named.append({
                        "address": f"0x{addr:08x}",
                        "name": fn_name,
                        "namespace": ns_name,
                    })

        # Table: classes with >= 3 functions, sorted by total desc
        class_nss = [ns for ns in ns_total if ns != "<global>" and ns_total[ns] >= 3]
        class_nss.sort(key=lambda ns: ns_total[ns], reverse=True)

        print(f"\n{'Class':<40} {'Total':>6} {'>=0.7':>6} {'>=0.9':>6} {'Cov%':>6}")
        print("-" * 66)
        for ns in class_nss[:40]:
            tot = ns_total[ns]
            m7 = ns_matched_07[ns]
            m9 = ns_matched_09[ns]
            print(f"{ns:<40} {tot:>6} {m7:>6} {m9:>6} {m7/tot*100:>5.0f}%")

        g_tot = ns_total["<global>"]
        g_m7 = ns_matched_07["<global>"]
        g_m9 = ns_matched_09["<global>"]
        g_pct = g_m7 / g_tot * 100 if g_tot else 0
        print(f"\n{'<global>':<40} {g_tot:>6} {g_m7:>6} {g_m9:>6} {g_pct:>5.0f}%")

        print(f"\n[unmatched named] {len(unmatched_named)} named main functions with no demo match")
        for r in unmatched_named[:10]:
            label = (
                f"{r['namespace']}::{r['name']}"
                if r["namespace"] != "<global>"
                else r["name"]
            )
            print(f"  {r['address']}  {label}")

        if args.coverage_csv:
            cov_path = Path(args.coverage_csv)
            if not cov_path.is_absolute():
                cov_path = root / cov_path
            cov_path.parent.mkdir(parents=True, exist_ok=True)
            cov_rows = []
            for ns in sorted(ns_total, key=lambda x: ns_total[x], reverse=True):
                tot = ns_total[ns]
                m7 = ns_matched_07[ns]
                m9 = ns_matched_09[ns]
                cov_rows.append({
                    "namespace": ns,
                    "total": tot,
                    "matched_07": m7,
                    "matched_09": m9,
                    "coverage_pct": f"{m7/tot*100:.1f}" if tot else "0.0",
                })
            with cov_path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=["namespace", "total", "matched_07", "matched_09", "coverage_pct"],
                )
                w.writeheader()
                w.writerows(cov_rows)
            print(f"[saved] coverage: {cov_path}")

        # ---------------------------------------------------------------
        # Item 3: Cross-validation spot-check
        # ---------------------------------------------------------------
        print("\n" + "=" * 70)
        print(f"ITEM 3: CROSS-VALIDATION (named main functions, sim >= {args.sim_spot_check})")
        print("=" * 70)

        spot_rows: list[dict] = []
        for fn in all_funcs:
            fn_name = fn.getName()
            if fn_name.startswith("FUN_") or fn_name.startswith("thunk_FUN_"):
                continue
            addr = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr not in main_to_best:
                continue
            best = main_to_best[addr]
            if float(best["similarity"]) < args.sim_spot_check:
                continue
            ns = fn.getParentNamespace()
            ns_name = ns.getName() if ns and ns != global_ns else ""
            spot_rows.append({
                "main_address": f"0x{addr:08x}",
                "main_name": fn_name,
                "main_namespace": ns_name,
                "demo_address": best["demo_address"],
                "demo_name": best["demo_name"],
                "similarity": best["similarity"],
            })

        spot_rows.sort(key=lambda r: float(r["similarity"]), reverse=True)
        print(f"\n[spot-check] {len(spot_rows)} named functions with sim >= {args.sim_spot_check}")
        print(f"\n{'Main name':<45} {'Demo name':<30} {'Sim':>6}")
        print("-" * 85)
        for r in spot_rows[:30]:
            main_label = (
                f"{r['main_namespace']}::{r['main_name']}"
                if r["main_namespace"]
                else r["main_name"]
            )
            print(f"{main_label:<45} {r['demo_name']:<30} {float(r['similarity']):>6.4f}")

        if args.spot_check_csv:
            sp_path = Path(args.spot_check_csv)
            if not sp_path.is_absolute():
                sp_path = root / sp_path
            sp_path.parent.mkdir(parents=True, exist_ok=True)
            with sp_path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "main_address", "main_name", "main_namespace",
                        "demo_address", "demo_name", "similarity",
                    ],
                )
                w.writeheader()
                w.writerows(spot_rows)
            print(f"[saved] spot-check: {sp_path}")

        # ---------------------------------------------------------------
        # Item 4: Ambiguous wrappers
        # ---------------------------------------------------------------
        print("\n" + "=" * 70)
        print(f"ITEM 4: AMBIGUOUS WRAPPERS (2+ demo matches at sim >= {args.sim_ambiguous})")
        print("=" * 70)

        ambig_rows: list[dict] = []
        for addr, matches in main_to_all.items():
            high = [m for m in matches if float(m["similarity"]) >= args.sim_ambiguous]
            if len(high) < 2:
                continue
            ambig_rows.append({
                "main_address": f"0x{addr:08x}",
                "main_name": high[0]["main_name"],
                "main_namespace": high[0]["main_namespace"],
                "match_count": len(high),
                "demo_addresses": ";".join(m["demo_address"] for m in high),
            })

        ambig_rows.sort(key=lambda r: r["match_count"], reverse=True)
        print(
            f"\n[ambiguous] {len(ambig_rows)} functions with 2+ demo matches "
            f"at sim >= {args.sim_ambiguous}"
        )
        print("  (generic structural patterns — exclude from class inference)")
        for r in ambig_rows[:15]:
            print(f"  {r['main_address']}  {r['main_name']}  ({r['match_count']} matches)")

        if args.ambiguous_csv:
            am_path = Path(args.ambiguous_csv)
            if not am_path.is_absolute():
                am_path = root / am_path
            am_path.parent.mkdir(parents=True, exist_ok=True)
            with am_path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "main_address", "main_name", "main_namespace",
                        "match_count", "demo_addresses",
                    ],
                )
                w.writeheader()
                w.writerows(ambig_rows)
            print(f"[saved] ambiguous: {am_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
