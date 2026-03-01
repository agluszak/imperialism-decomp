#!/usr/bin/env python3
"""
Query BSim H2 database for structurally similar function pairs (main binary vs demo).

Scans all functions in Imperialism.exe using the BSim GenSignatures engine, submits a
bulk QueryNearest against the H2 database, and emits a CSV of matches against
Imperialism Demo.exe (or another executable via --match-exe).

Output CSV columns:
  main_address, main_name, main_namespace, demo_address, demo_name, similarity, confidence

Prerequisite: run ``setup_bsim_db`` first to populate the H2 database.

Usage:
  uv run impk query_bsim_matches --out-csv tmp_decomp/bsim_matches_v1.csv
  uv run impk query_bsim_matches --out-csv tmp_decomp/bsim_matches_v1.csv --similarity 0.7
  uv run impk query_bsim_matches --out-csv tmp_decomp/bsim_matches_unresolved_v1.csv --only-unresolved
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, get_runtime_config, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Query BSim for similar functions between main binary and demo.",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument(
        "--db-dir",
        default=None,
        help="Directory with BSim H2 database (default: <project_root>/bsim_db)",
    )
    ap.add_argument(
        "--similarity",
        type=float,
        default=0.7,
        help="Minimum similarity threshold (default: 0.7)",
    )
    ap.add_argument(
        "--confidence",
        type=float,
        default=0.0,
        help="Minimum confidence (significance) threshold (default: 0.0)",
    )
    ap.add_argument(
        "--max-matches",
        type=int,
        default=5,
        help="Maximum matches per function (default: 5)",
    )
    ap.add_argument(
        "--match-exe",
        default="Imperialism Demo.exe",
        help="Filter results to this executable name (default: 'Imperialism Demo.exe')",
    )
    ap.add_argument(
        "--only-unresolved",
        action="store_true",
        help="Skip main functions already named (not starting with FUN_/thunk_FUN_)",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    db_dir = Path(args.db_dir) if args.db_dir else root / "bsim_db"
    db_path = db_dir / "imperialism"
    db_url = f"file://{db_path}"

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    mv_db = db_dir / "imperialism.mv.db"
    if not mv_db.exists():
        print(f"[error] BSim DB not found: {mv_db}")
        print("  Run: uv run impk setup_bsim_db")
        return 1

    print(f"[config] db_url    = {db_url}")
    print(f"[config] match_exe = {args.match_exe}")
    print(f"[config] similarity >= {args.similarity}, confidence >= {args.confidence}")
    print(f"[config] max_matches = {args.max_matches}")

    with open_program(root) as program:
        from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
        from ghidra.features.bsim.query.protocol import QueryNearest

        database = None
        gensig = None
        try:
            url = BSimClientFactory.deriveBSimURL(db_url)
            database = BSimClientFactory.buildClient(url, False)
            database.initialize()

            gensig = GenSignatures(False)
            gensig.setVectorFactory(database.getLSHVectorFactory())
            gensig.openProgram(program, None, None, None, None, None)

            fm = program.getFunctionManager()
            global_ns = program.getGlobalNamespace()

            # Pre-build address -> namespace map to avoid per-result lookups
            fn_addr_to_ns: dict[int, str] = {}
            fit = fm.getFunctions(True)
            while fit.hasNext():
                fn = fit.next()
                ns = fn.getParentNamespace()
                if ns is not None and ns != global_ns:
                    fn_addr_to_ns[fn.getEntryPoint().getOffset() & 0xFFFFFFFF] = ns.getName()

            # Collect functions to scan
            functions_to_scan = []
            fit = fm.getFunctions(True)
            while fit.hasNext():
                fn = fit.next()
                fn_name = fn.getName()
                if args.only_unresolved:
                    if not fn_name.startswith("FUN_") and not fn_name.startswith("thunk_FUN_"):
                        continue
                functions_to_scan.append(fn)

            print(f"[scan] functions to scan: {len(functions_to_scan)}")

            # Scan all functions to build feature vectors in the DescriptionManager
            scanned = 0
            scan_fail = 0
            for i, fn in enumerate(functions_to_scan):
                try:
                    gensig.scanFunction(fn)
                    scanned += 1
                except Exception:
                    scan_fail += 1
                if (i + 1) % 1000 == 0:
                    print(f"  [progress] scanned {i + 1}/{len(functions_to_scan)}")

            print(f"[scan] scanned={scanned} scan_fail={scan_fail}")

            # Submit bulk query
            query = QueryNearest()
            query.manage = gensig.getDescriptionManager()
            query.max = args.max_matches
            query.thresh = args.similarity
            query.signifthresh = args.confidence

            print(f"[query] submitting QueryNearest ...")
            response = database.query(query)

            # Process results
            rows = []
            match_exe = args.match_exe

            if response is None:
                print("[warn] null response from BSim query")
            elif not hasattr(response, "result") or response.result is None:
                print("[warn] response has no result field")
            else:
                for simresult in response.result:
                    base_desc = simresult.getBase()
                    main_addr = base_desc.getAddress() & 0xFFFFFFFF
                    main_name = base_desc.getFunctionName()
                    main_ns = fn_addr_to_ns.get(main_addr, "")

                    it = simresult.iterator()
                    while it.hasNext():
                        note = it.next()
                        sim = float(note.getSimilarity())
                        conf = float(note.getSignificance())
                        match_desc = note.getFunctionDescription()
                        exe_name = match_desc.getExecutableRecord().getNameExec()

                        # Filter to the target executable only
                        if exe_name != match_exe:
                            continue

                        demo_addr = match_desc.getAddress() & 0xFFFFFFFF
                        demo_name = match_desc.getFunctionName()

                        rows.append({
                            "main_address": f"0x{main_addr:08x}",
                            "main_name": main_name,
                            "main_namespace": main_ns,
                            "demo_address": f"0x{demo_addr:08x}",
                            "demo_name": demo_name,
                            "similarity": f"{sim:.4f}",
                            "confidence": f"{conf:.4f}",
                        })

            print(f"[results] total pairs: {len(rows)}")

            # Sort by similarity descending, then main_address ascending
            rows.sort(key=lambda r: (-float(r["similarity"]), int(r["main_address"], 16)))

            with out_csv.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "main_address", "main_name", "main_namespace",
                        "demo_address", "demo_name", "similarity", "confidence",
                    ],
                )
                w.writeheader()
                w.writerows(rows)

            # Summary stats
            if rows:
                high = sum(1 for r in rows if float(r["similarity"]) >= 0.9)
                med = sum(1 for r in rows if 0.7 <= float(r["similarity"]) < 0.9)
                print(f"[stats] sim>=0.9: {high}  0.7<=sim<0.9: {med}")

            print(f"[saved] {out_csv}")

        finally:
            if gensig is not None:
                try:
                    gensig.dispose()
                except Exception:
                    pass
            if database is not None:
                try:
                    database.close()
                except Exception:
                    pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
