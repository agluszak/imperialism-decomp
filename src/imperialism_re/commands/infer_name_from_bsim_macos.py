#!/usr/bin/env python3
"""
Propose Windows function names and class assignments by BSim matching against the macOS binary.

For each Windows function the BSim QueryNearest finds a match in the macOS binary:
  1. Load macos_class_methods.csv → addr_to_info: macos_addr → (class_name, method_name)
  2. Open Imperialism.exe; run GenSignatures for all (or only unresolved) functions
  3. QueryNearest against the BSim database, filtering results to the macOS executable
  4. For each (win_fn, macos_fn) pair where macos_fn is in addr_to_info:
     → emit (address, class_name, new_name, similarity, confidence, evidence)
  5. Sort by similarity descending

Confidence rules:
  high   — unnamed Windows function (FUN_*, thunk_FUN_*) with similarity ≥ 0.9
  medium — named Windows function differing from macOS name, or similarity 0.7–0.9
  low    — similarity < 0.7 (review-only; not for bulk auto-apply)

Output CSV is directly compatible with attach_functions_to_class_csv (columns:
address, class_name, new_name).  Extra columns aid review but are ignored by apply commands.

Prerequisite: Imperialism_macos must be indexed in the BSim database.  Run
  uv run impk setup_bsim_db
or
  uv run impk setup_bsim_db --force-recreate
if the macOS binary was added to the Ghidra project after the last BSim setup.

Usage:
  uv run impk infer_name_from_bsim_macos \\
      --out-csv tmp_decomp/bsim_macos_name_candidates.csv \\
      --similarity 0.9 --only-unresolved
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, get_runtime_config, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def _is_unresolved(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or (name.startswith("thunk_") and "FUN_" in name)
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Propose Windows function names/classes via BSim macOS matching.",
    )
    ap.add_argument(
        "--macos-csv",
        default="tmp_decomp/macos_class_methods.csv",
        help="macOS class methods CSV (default: tmp_decomp/macos_class_methods.csv)",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/bsim_macos_name_candidates.csv",
        help="Output candidates CSV (default: tmp_decomp/bsim_macos_name_candidates.csv)",
    )
    ap.add_argument(
        "--match-exe",
        default="Imperialism_macos",
        help="macOS executable name as stored in BSim (default: Imperialism_macos)",
    )
    ap.add_argument(
        "--similarity",
        type=float,
        default=0.7,
        help="Minimum similarity threshold (default: 0.7)",
    )
    ap.add_argument(
        "--confidence-threshold",
        type=float,
        default=0.0,
        help="Minimum BSim significance/confidence threshold (default: 0.0)",
    )
    ap.add_argument(
        "--max-matches",
        type=int,
        default=3,
        help="Maximum BSim matches per Windows function (default: 3)",
    )
    ap.add_argument(
        "--only-unresolved",
        action="store_true",
        help="Only scan unnamed Windows functions (FUN_*, thunk_FUN_*)",
    )
    ap.add_argument(
        "--db-dir",
        default=None,
        help="Directory with BSim H2 database (default: <project_root>/bsim_db)",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    macos_csv_path = Path(args.macos_csv)
    if not macos_csv_path.is_absolute():
        macos_csv_path = root / macos_csv_path
    if not macos_csv_path.exists():
        print(f"[error] macOS CSV not found: {macos_csv_path}")
        return 1

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    db_dir = Path(args.db_dir) if args.db_dir else root / "bsim_db"
    db_path = db_dir / "imperialism"
    db_url = f"file://{db_path}"

    mv_db = db_dir / "imperialism.mv.db"
    if not mv_db.exists():
        print(f"[error] BSim DB not found: {mv_db}")
        print("  Run: uv run impk setup_bsim_db")
        return 1

    # Load macOS class methods CSV: addr → (class_name, method_name)
    addr_to_info: dict[int, tuple[str, str]] = {}
    with macos_csv_path.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cls = row.get("class", "").strip()
            method = row.get("method", "").strip()
            addr_str = row.get("address", "").strip()
            if not cls or not method or not addr_str:
                continue
            try:
                addr_int = int(addr_str, 16)
            except ValueError:
                continue
            addr_to_info[addr_int] = (cls, method)

    print(f"[macos_csv] {len(addr_to_info)} class method addresses loaded")

    rows: list[dict] = []

    with open_program(root) as program:
        from ghidra.features.bsim.query import BSimClientFactory, GenSignatures  # noqa: PLC0415
        from ghidra.features.bsim.query.protocol import QueryNearest  # noqa: PLC0415

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

            # Build address → current namespace map
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
                if args.only_unresolved and not _is_unresolved(fn.getName()):
                    continue
                functions_to_scan.append(fn)

            print(f"[scan] functions to scan: {len(functions_to_scan)}")

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

            query = QueryNearest()
            query.manage = gensig.getDescriptionManager()
            query.max = args.max_matches
            query.thresh = args.similarity
            query.signifthresh = args.confidence_threshold

            print("[query] submitting QueryNearest ...")
            response = database.query(query)

            match_exe = args.match_exe
            skipped_not_in_csv = 0

            if response is None:
                print("[warn] null response from BSim query")
            elif not hasattr(response, "result") or response.result is None:
                print("[warn] response has no result field")
            else:
                for simresult in response.result:
                    base_desc = simresult.getBase()
                    win_addr = base_desc.getAddress() & 0xFFFFFFFF
                    win_name = base_desc.getFunctionName()
                    win_ns = fn_addr_to_ns.get(win_addr, "")

                    # Take the best macOS match above threshold
                    best_sim = 0.0
                    best_info = None
                    best_macos_addr = 0

                    it = simresult.iterator()
                    while it.hasNext():
                        note = it.next()
                        match_desc = note.getFunctionDescription()
                        if match_desc.getExecutableRecord().getNameExec() != match_exe:
                            continue
                        sim = float(note.getSimilarity())
                        macos_addr = match_desc.getAddress() & 0xFFFFFFFF
                        info = addr_to_info.get(macos_addr)
                        if info is None:
                            continue
                        if sim > best_sim:
                            best_sim = sim
                            best_info = info
                            best_macos_addr = macos_addr

                    if best_info is None:
                        skipped_not_in_csv += 1
                        continue

                    cls_name, method_name = best_info

                    # Determine confidence
                    is_unresolved_win = _is_unresolved(win_name)
                    if is_unresolved_win and best_sim >= 0.9:
                        confidence = "high"
                    elif best_sim >= 0.9 or (is_unresolved_win and best_sim >= 0.7):
                        confidence = "medium"
                    else:
                        confidence = "low"

                    rows.append({
                        "address": f"0x{win_addr:08x}",
                        "class_name": cls_name,
                        "new_name": method_name,
                        "current_name": win_name,
                        "current_namespace": win_ns,
                        "similarity": f"{best_sim:.4f}",
                        "confidence": confidence,
                        "evidence": f"bsim_macos_0x{best_macos_addr:08x}",
                    })

            print(f"[results] {len(rows)} candidates (skipped {skipped_not_in_csv} matches not in CSV)")

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

    rows.sort(key=lambda r: -float(r["similarity"]))

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address", "class_name", "new_name",
                "current_name", "current_namespace",
                "similarity", "confidence", "evidence",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    high = sum(1 for r in rows if r["confidence"] == "high")
    med = sum(1 for r in rows if r["confidence"] == "medium")
    low = sum(1 for r in rows if r["confidence"] == "low")
    print(f"[saved] {out_csv} rows={len(rows)} (high={high} medium={med} low={low})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
