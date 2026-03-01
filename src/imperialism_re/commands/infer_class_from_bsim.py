#!/usr/bin/env python3
"""
Infer class membership for unresolved Global __thiscall functions via BSim demo match neighborhoods.

Algorithm:
  1. Load BSim matches CSV -> build demo_addr->main_class anchors and unresolved_main->demo_matches
  2. Open Imperialism Demo.exe in Ghidra
  3. For each unresolved main FUN_ with a demo match at sim >= threshold:
     - Get callers of the matched demo function in the demo binary
     - Map each demo caller address back to its main class (via CSV anchors)
     - Vote: if callers consistently belong to one main class, assign it

Output CSV (compatible with apply_class_quads_from_csv):
  address, name, class_name, confidence, evidence

Usage:
  uv run impk infer_class_from_bsim \\
      --in-csv tmp_decomp/bsim_matches_v1.csv \\
      --out-csv tmp_decomp/bsim_class_infer.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program_path


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Infer class membership via BSim demo caller neighborhoods.",
    )
    ap.add_argument("--in-csv", required=True, help="BSim matches CSV from query_bsim_matches")
    ap.add_argument("--out-csv", required=True, help="Output class inference CSV")
    ap.add_argument(
        "--demo-program-path",
        default="/Imperialism Demo.exe",
        help="Ghidra program path for the demo binary (default: '/Imperialism Demo.exe')",
    )
    ap.add_argument(
        "--similarity",
        type=float,
        default=0.9,
        help="Min similarity to use a match as evidence (default: 0.9)",
    )
    ap.add_argument(
        "--min-evidence",
        type=int,
        default=2,
        help="Min class-voting callers to emit a result (default: 2)",
    )
    ap.add_argument(
        "--min-ratio",
        type=float,
        default=0.67,
        help="Min ratio of top-class callers for medium confidence (default: 0.67)",
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

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    print(f"[load] {len(rows)} rows from {in_csv}")

    # Build demo anchor map and unresolved candidate map from CSV
    demo_ns_votes: dict[int, Counter] = defaultdict(Counter)
    unresolved_main: dict[int, list[tuple[int, float]]] = defaultdict(list)
    main_addr_to_name: dict[int, str] = {}

    for row in rows:
        sim = float(row["similarity"])
        if sim < args.similarity:
            continue
        main_addr = int(row["main_address"], 16)
        demo_addr = int(row["demo_address"], 16)
        main_ns = row["main_namespace"].strip()
        main_name = row["main_name"].strip()

        main_addr_to_name[main_addr] = main_name

        # Demo functions matched by classified main funcs become class anchors
        if main_ns:
            demo_ns_votes[demo_addr][main_ns] += 1

        # Unresolved main funcs are inference candidates
        if main_name.startswith("FUN_") or main_name.startswith("thunk_FUN_"):
            unresolved_main[main_addr].append((demo_addr, sim))

    # Resolve demo_addr -> class (require consensus: single class or 80%+ majority)
    demo_addr_to_class: dict[int, str] = {}
    for demo_addr, votes in demo_ns_votes.items():
        if len(votes) == 1:
            demo_addr_to_class[demo_addr] = next(iter(votes))
        else:
            top_cls, top_cnt = votes.most_common(1)[0]
            if top_cnt / sum(votes.values()) >= 0.8:
                demo_addr_to_class[demo_addr] = top_cls

    print(f"[anchors] demo functions with clear main class: {len(demo_addr_to_class)}")
    print(f"[candidates] unresolved main functions with demo match: {len(unresolved_main)}")

    conf_rank = {"high": 3, "medium": 2, "low": 1}
    results: list[dict] = []

    with open_program_path(root, args.demo_program_path) as demo_program:
        demo_fm = demo_program.getFunctionManager()
        demo_rm = demo_program.getReferenceManager()
        demo_af = demo_program.getAddressFactory().getDefaultAddressSpace()

        processed = 0
        for main_addr, demo_matches in unresolved_main.items():
            processed += 1
            if processed % 500 == 0:
                print(f"  [progress] {processed}/{len(unresolved_main)}")

            class_votes: Counter = Counter()
            total_callers = 0
            classified_callers = 0

            for demo_addr, _sim in sorted(demo_matches, key=lambda x: x[1], reverse=True):
                demo_ga = demo_af.getAddress(f"0x{demo_addr:08x}")
                refs = demo_rm.getReferencesTo(demo_ga)
                for ref in refs:
                    caller_fn = demo_fm.getFunctionContaining(ref.getFromAddress())
                    if caller_fn is None:
                        continue
                    caller_entry = caller_fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                    total_callers += 1
                    cls = demo_addr_to_class.get(caller_entry)
                    if cls:
                        class_votes[cls] += 1
                        classified_callers += 1

            if not class_votes or classified_callers < args.min_evidence:
                continue

            top_cls, top_cnt = class_votes.most_common(1)[0]
            ratio = top_cnt / classified_callers

            if ratio == 1.0 and classified_callers >= 3:
                confidence = "high"
            elif ratio >= args.min_ratio:
                confidence = "medium"
            else:
                confidence = "low"

            main_name = main_addr_to_name.get(main_addr, f"FUN_{main_addr:08x}")
            results.append({
                "address": f"0x{main_addr:08x}",
                "name": main_name,
                "class_name": top_cls,
                "confidence": confidence,
                "evidence": (
                    f"bsim_demo_{top_cls}={top_cnt}_of_{classified_callers}"
                    f"_total={total_callers}_demos={len(demo_matches)}"
                ),
            })

    results.sort(key=lambda r: (-conf_rank[r["confidence"]], int(r["address"], 16)))

    print(f"\n[results] total: {len(results)}")
    conf_dist = Counter(r["confidence"] for r in results)
    cls_dist = Counter(r["class_name"] for r in results)
    print(f"[confidence] {dict(conf_dist)}")
    print("[top classes]")
    for cls, cnt in cls_dist.most_common(15):
        print(f"  {cls}: {cnt}")

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["address", "name", "class_name", "confidence", "evidence"]
        )
        w.writeheader()
        w.writerows(results)

    print(f"[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
