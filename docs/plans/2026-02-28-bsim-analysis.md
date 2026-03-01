# BSim Analysis & Class Inference Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build two new commands — `analyze_bsim_results` (coverage map, spot-check, ambiguous wrapper detection) and `infer_class_from_bsim` (class assignment from demo caller neighborhoods) — plus the `open_program_path` core helper they need.

**Architecture:** `analyze_bsim_results` opens `Imperialism.exe` + reads the BSim matches CSV to produce three reports. `infer_class_from_bsim` reads the CSV to build demo→class anchors, then opens `Imperialism Demo.exe` to walk caller neighborhoods and vote for class membership. A new `open_program_path(root, path)` helper in `core/ghidra_session.py` enables opening an arbitrary program from the project.

**Tech Stack:** Python 3.12, pyghidra, Ghidra Java API (`FunctionManager`, `ReferenceManager`), CSV stdlib.

---

## Task 1: Add `open_program_path` to `core/ghidra_session.py`

**Files:**
- Modify: `src/imperialism_re/core/ghidra_session.py`

**Step 1: Read the existing file**

Read `src/imperialism_re/core/ghidra_session.py` to understand current structure.

**Step 2: Add the helper**

Append after the existing `open_program` function:

```python
@contextmanager
def open_program_path(project_root: Path | None, program_path: str) -> Iterator[object]:
    """Open an arbitrary program from the Ghidra project by path."""
    cfg = get_runtime_config(project_root)
    _start_pyghidra(cfg)
    project = _open_project(cfg)
    with pyghidra.program_context(project, program_path) as program:
        yield program
```

**Step 3: Verify syntax**

Run: `uv run python -c "from imperialism_re.core.ghidra_session import open_program_path; print('OK')"`
Expected: `OK`

---

## Task 2: Create `analyze_bsim_results.py`

**Files:**
- Create: `src/imperialism_re/commands/analyze_bsim_results.py`

**Step 1: Write the file**

```python
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

        # Print table: classes with >= 3 functions, sorted by total desc
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
            label = f"{r['namespace']}::{r['name']}" if r["namespace"] != "<global>" else r["name"]
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
        print(f"\n[ambiguous] {len(ambig_rows)} functions with 2+ demo matches at sim >= {args.sim_ambiguous}")
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
```

**Step 2: Verify syntax**

Run: `uv run python -m py_compile src/imperialism_re/commands/analyze_bsim_results.py && echo OK`
Expected: `OK`

---

## Task 3: Create `infer_class_from_bsim.py`

**Files:**
- Create: `src/imperialism_re/commands/infer_class_from_bsim.py`

**Step 1: Write the file**

```python
#!/usr/bin/env python3
"""
Infer class membership for unresolved Global __thiscall functions via BSim demo match neighborhoods.

Algorithm:
  1. Load BSim matches CSV → build demo_addr→main_class anchors and unresolved_main→demo_matches
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
```

**Step 2: Verify syntax**

Run: `uv run python -m py_compile src/imperialism_re/commands/infer_class_from_bsim.py && echo OK`
Expected: `OK`

---

## Task 4: Update catalog and test count

**Files:**
- Modify: `src/imperialism_re/command_catalog.yaml`
- Modify: `tests/test_tooling_smoke.py`

**Step 1: Add catalog entries**

Add after the `query_bsim_matches` entry (before `run_qc_pass`):

```yaml
  - name: analyze_bsim_results
    module: imperialism_re.commands.analyze_bsim_results
    mode: reader
    status: maintained
    summary: Coverage map, cross-validation spot-check, and ambiguous wrapper detection from BSim matches CSV.
  - name: infer_class_from_bsim
    module: imperialism_re.commands.infer_class_from_bsim
    mode: reader
    status: maintained
    summary: Infer class membership for unresolved thiscall functions via BSim demo caller neighborhoods.
```

**Step 2: Update test count**

In `tests/test_tooling_smoke.py`, change:
```python
self.assertEqual(100, len(catalog))
```
to:
```python
self.assertEqual(102, len(catalog))
```

**Step 3: Run tests**

Run: `uv run pytest tests/test_tooling_smoke.py -q`
Expected: 1 failed (pre-existing `test_no_cross_command_imports`), 11 passed

---

## Task 5: Run `analyze_bsim_results` and verify output

**Step 1: Run full analysis with all CSV outputs**

```bash
uv run impk analyze_bsim_results \
    --in-csv tmp_decomp/bsim_matches_v1.csv \
    --coverage-csv tmp_decomp/bsim_coverage.csv \
    --spot-check-csv tmp_decomp/bsim_spot_check.csv \
    --ambiguous-csv tmp_decomp/bsim_ambiguous.csv
```

Expected output contains:
- Coverage table with class namespaces and percentages
- Spot-check table showing named functions matching demo at sim >= 0.95
- Ambiguous wrappers list

**Step 2: Sanity-check CSVs**

```bash
head -5 tmp_decomp/bsim_coverage.csv
head -5 tmp_decomp/bsim_spot_check.csv
head -5 tmp_decomp/bsim_ambiguous.csv
```

---

## Task 6: Run `infer_class_from_bsim` and verify output

**Step 1: Run inference**

```bash
uv run impk infer_class_from_bsim \
    --in-csv tmp_decomp/bsim_matches_v1.csv \
    --out-csv tmp_decomp/bsim_class_infer.csv
```

Expected: some number of class assignments emitted, confidence distribution printed.

**Step 2: Preview results**

```bash
head -20 tmp_decomp/bsim_class_infer.csv
```

Expected: rows with address, name (FUN_...), class_name, confidence (high/medium/low), evidence string.
