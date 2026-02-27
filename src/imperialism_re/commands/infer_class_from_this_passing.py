#!/usr/bin/env python3
"""
Infer class membership for Global __thiscall functions by detecting
this-pointer passing from already-classified class methods.

When a classified class method calls a Global ``__thiscall`` function and
passes its own ``this``/``param_1`` as the first argument, the callee likely
operates on the same class.

Algorithm:
  1. Build fn_name → class_name map for all class-namespaced functions
  2. Build fn_name → addr map for Global __thiscall void* candidates
  3. For each class, decompile all its methods
  4. Find call patterns where this/param_1 is the first argument
  5. If the callee matches a Global __thiscall candidate, vote for the caller's class
  6. Aggregate votes; emit if consensus >= --min-ratio

Output CSV columns:
  address, name, class_name, confidence, evidence

Usage:
  uv run impk infer_class_from_this_passing --out-csv tmp_decomp/this_passing_infer.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


# Pattern: FuncName(this, ...)  or  FuncName(param_1, ...)  or  FuncName(pThis, ...)
_THIS_PASS = re.compile(
    r"(\w+)\s*\(\s*(?:this|param_1|pThis)\s*(?:,|\))"
)


def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 20, None)
    if not res or not res.decompileCompleted():
        return ""
    dc = res.getDecompiledFunction()
    if dc is None:
        return ""
    return str(dc.getC())


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Infer class membership for Global __thiscall functions "
        "via this-pointer passing from classified class methods.",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-classes", type=int, default=0, help="Limit classes (0=all)")
    ap.add_argument(
        "--min-ratio",
        type=float,
        default=0.67,
        help="Minimum ratio of top class votes for medium confidence (default 0.67)",
    )
    ap.add_argument(
        "--min-votes",
        type=int,
        default=1,
        help="Minimum total votes across class methods to emit (default 1)",
    )
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

        # Build class namespace set
        class_names = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            cls = it_cls.next()
            class_names.add(cls.getName())

        # Step 1: Build fn_name → class_name map for class-namespaced functions
        fn_name_to_class: dict[str, str] = {}
        # Also build class_name → [function] map for decompilation
        class_methods: dict[str, list] = {}
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            ns_name = ns.getName()
            if ns_name in class_names:
                fn_name_to_class[fn.getName()] = ns_name
                class_methods.setdefault(ns_name, []).append(fn)

        print(f"[init] known classes: {len(class_names)}")
        print(f"[init] class-namespaced functions: {len(fn_name_to_class)}")
        print(f"[init] classes with methods: {len(class_methods)}")

        # Step 2: Build candidate set — Global __thiscall void* functions
        candidate_names: dict[str, int] = {}  # fn_name → addr
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is not None and ns != global_ns:
                continue
            cc = fn.getCallingConventionName()
            if cc != "__thiscall":
                continue
            params = list(fn.getParameters())
            if not params:
                continue
            p0_type = params[0].getDataType().getName()
            if "void *" not in p0_type and p0_type != "void *":
                continue
            addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            candidate_names[fn.getName()] = addr_int

        print(f"[init] Global __thiscall void* candidates: {len(candidate_names)}")

        # Step 3: Set up decompiler
        ifc = DecompInterface()
        ifc.openProgram(program)

        # Step 4: For each class, decompile its methods and find this-passing calls
        # Accumulate: candidate_name → Counter(class_name → vote_count)
        candidate_votes: dict[str, Counter] = {}
        classes_processed = 0
        methods_decompiled = 0

        for cls_name, methods in sorted(class_methods.items()):
            if args.max_classes and classes_processed >= args.max_classes:
                break
            classes_processed += 1

            for method_fn in methods:
                c_code = decompile_text(ifc, method_fn)
                if not c_code:
                    continue
                methods_decompiled += 1

                # Find all calls passing this/param_1 as first argument
                for m in _THIS_PASS.finditer(c_code):
                    callee_name = m.group(1)
                    if callee_name in candidate_names:
                        if callee_name not in candidate_votes:
                            candidate_votes[callee_name] = Counter()
                        candidate_votes[callee_name][cls_name] += 1

            if classes_processed % 50 == 0:
                print(
                    f"  [progress] classes: {classes_processed}/{len(class_methods)}, "
                    f"methods decompiled: {methods_decompiled}, "
                    f"candidates with votes: {len(candidate_votes)}"
                )

        ifc.dispose()

        print(f"[scan] classes processed: {classes_processed}")
        print(f"[scan] methods decompiled: {methods_decompiled}")
        print(f"[scan] candidates with votes: {len(candidate_votes)}")

        # Step 5: Aggregate votes and emit results
        results = []
        for cand_name, votes in candidate_votes.items():
            total = sum(votes.values())
            if total < args.min_votes:
                continue

            top_cls, top_count = votes.most_common(1)[0]
            ratio = top_count / total

            if ratio == 1.0 and top_count >= 2:
                confidence = "high"
            elif ratio >= args.min_ratio:
                confidence = "medium"
            else:
                confidence = "low"

            evidence_parts = [f"{cls}={cnt}" for cls, cnt in votes.most_common(3)]
            evidence = f"this_pass_total={total}_" + "_".join(evidence_parts)

            results.append({
                "address": f"0x{candidate_names[cand_name]:08x}",
                "name": cand_name,
                "class_name": top_cls,
                "confidence": confidence,
                "evidence": evidence,
            })

        print(f"[results] total: {len(results)}")

        # Deduplicate: prefer higher confidence
        conf_rank = {"high": 3, "medium": 2, "low": 1}
        addr_best: dict[str, dict] = {}
        for r in results:
            addr = r["address"]
            if addr not in addr_best or conf_rank[r["confidence"]] > conf_rank.get(
                addr_best[addr]["confidence"], 0
            ):
                addr_best[addr] = r

        deduped = sorted(addr_best.values(), key=lambda r: int(r["address"], 16))
        print(f"[deduped] {len(deduped)}")

        # Write CSV
        fieldnames = ["address", "name", "class_name", "confidence", "evidence"]
        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(deduped)

        # Stats
        conf_dist = Counter(r["confidence"] for r in deduped)
        cls_dist = Counter(r["class_name"] for r in deduped)
        print(f"\n[confidence] {dict(conf_dist)}")
        print(f"[top classes]")
        for cls, cnt in cls_dist.most_common(15):
            print(f"  {cls}: {cnt}")

    print(f"\n[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
