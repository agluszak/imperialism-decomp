#!/usr/bin/env python3
"""
Infer class membership for Global __thiscall functions via caller namespace analysis.

Instead of decompiling each candidate, this command looks at who *calls* the function.
If all (or most) classified callers belong to one class, the function likely belongs
to that class too.

No decompilation needed — pure reference + namespace analysis.

Output CSV columns:
  address, name, class_name, confidence, evidence

Usage:
  uv run impk infer_class_from_callers --out-csv tmp_decomp/caller_infer.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def _get_thunk_target(fn, fm):
    """If *fn* is a simple thunk (calls exactly 1 other function), return that target."""
    body = fn.getBody()
    if body is None:
        return None
    if body.getNumAddresses() > 40:
        return None
    thunked = fn.getThunkedFunction(False)
    if thunked is not None:
        return thunked
    called = set()
    refs = fn.getCalledFunctions(None)
    if refs is not None:
        for callee in refs:
            called.add(callee)
    if len(called) == 1:
        return list(called)[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Infer class membership for Global __thiscall functions "
        "via caller namespace analysis.",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-functions", type=int, default=0, help="Limit (0=all)")
    ap.add_argument(
        "--min-callers",
        type=int,
        default=2,
        help="Minimum classified callers to emit a result (default 2)",
    )
    ap.add_argument(
        "--min-ratio",
        type=float,
        default=0.67,
        help="Minimum ratio of top-class callers for medium confidence (default 0.67)",
    )
    ap.add_argument(
        "--confidence-filter",
        choices=["high", "medium", "low"],
        default=None,
        help="Only emit rows at or above this confidence level",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    conf_rank = {"high": 3, "medium": 2, "low": 1}
    conf_filter_rank = conf_rank.get(args.confidence_filter, 0)

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with open_program(root) as program:
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        global_ns = program.getGlobalNamespace()
        af = program.getAddressFactory().getDefaultAddressSpace()

        # --- Step 1: Build class namespace set and fn_addr -> class_name map ---
        class_names = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            cls = it_cls.next()
            class_names.add(cls.getName())

        fn_to_class: dict[int, str] = {}  # entry-point offset -> class name
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            ns_name = ns.getName()
            if ns_name in class_names:
                addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                fn_to_class[addr_int] = ns_name

        print(f"[init] known classes: {len(class_names)}")
        print(f"[init] class-namespaced functions: {len(fn_to_class)}")

        # --- Step 2: Build bidirectional thunk index ---
        # For each function, collect the set of addresses that are "the same"
        # (the function itself + all thunks pointing to it, or its thunk target).
        thunk_to_target: dict[int, int] = {}  # thunk addr -> real target addr
        target_to_thunks: dict[int, set[int]] = {}  # real target -> {thunk addrs}

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            target = _get_thunk_target(fn, fm)
            if target is not None:
                t_addr = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                tgt_addr = target.getEntryPoint().getOffset() & 0xFFFFFFFF
                if t_addr != tgt_addr:
                    thunk_to_target[t_addr] = tgt_addr
                    target_to_thunks.setdefault(tgt_addr, set()).add(t_addr)

        print(f"[init] thunk pairs: {len(thunk_to_target)}")

        # --- Step 3: Collect candidates (Global __thiscall void* first param) ---
        candidates = []
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
            candidates.append(fn)

        print(f"[candidates] Global __thiscall void*: {len(candidates)}")

        # --- Step 4: Per-candidate caller analysis ---
        results = []
        count = 0

        for fn in candidates:
            if args.max_functions and count >= args.max_functions:
                break
            count += 1

            addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            fn_name = fn.getName()

            # Build thunk equivalence group: this function + all thunks to/from it
            equiv_addrs = {addr_int}
            # If this function is a thunk, include the real target
            if addr_int in thunk_to_target:
                equiv_addrs.add(thunk_to_target[addr_int])
            # If other thunks point to this function, include them
            if addr_int in target_to_thunks:
                equiv_addrs.update(target_to_thunks[addr_int])
            # Also include thunks of thunks (one level)
            for ea in list(equiv_addrs):
                if ea in target_to_thunks:
                    equiv_addrs.update(target_to_thunks[ea])

            # Collect caller classes from references to all addresses in the group
            caller_classes = Counter()
            total_callers = 0
            unclassified_callers = 0

            seen_caller_addrs = set()
            for ea in equiv_addrs:
                ga = af.getAddress(f"0x{ea:08x}")
                refs = rm.getReferencesTo(ga)
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    caller_fn = fm.getFunctionContaining(from_addr)
                    if caller_fn is None:
                        continue
                    caller_entry = caller_fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                    # Skip self-references and references from within the equiv group
                    if caller_entry in equiv_addrs:
                        continue
                    if caller_entry in seen_caller_addrs:
                        continue
                    seen_caller_addrs.add(caller_entry)

                    total_callers += 1

                    # Direct vote: caller is in a class namespace
                    if caller_entry in fn_to_class:
                        caller_classes[fn_to_class[caller_entry]] += 1
                        continue

                    # Indirect vote: caller is an unclassified thunk — check
                    # one level deeper for class-namespaced callers of the thunk
                    if caller_entry in thunk_to_target or caller_entry in target_to_thunks:
                        # This caller is a thunk; check its own callers
                        thunk_equiv = {caller_entry}
                        if caller_entry in thunk_to_target:
                            thunk_equiv.add(thunk_to_target[caller_entry])
                        if caller_entry in target_to_thunks:
                            thunk_equiv.update(target_to_thunks[caller_entry])

                        found_indirect = False
                        for tea in thunk_equiv:
                            if tea in fn_to_class:
                                caller_classes[fn_to_class[tea]] += 1
                                found_indirect = True
                                break
                        if found_indirect:
                            continue

                    unclassified_callers += 1

            classified_count = sum(caller_classes.values())
            if classified_count < args.min_callers or not caller_classes:
                continue

            top_cls, top_count = caller_classes.most_common(1)[0]
            ratio = top_count / classified_count

            # Score
            if ratio == 1.0:
                confidence = "high"
            elif ratio >= args.min_ratio:
                confidence = "medium"
            else:
                confidence = "low"

            if conf_rank[confidence] < conf_filter_rank:
                continue

            evidence = (
                f"callers_{top_cls}={top_count}_of_{classified_count}"
                f"_total={total_callers}_unclass={unclassified_callers}"
            )
            results.append({
                "address": f"0x{addr_int:08x}",
                "name": fn_name,
                "class_name": top_cls,
                "confidence": confidence,
                "evidence": evidence,
            })

            if count % 200 == 0:
                print(f"  [progress] analyzed {count}, results so far: {len(results)}")

        print(f"[scan] analyzed: {count} of {len(candidates)}")
        print(f"[results] total: {len(results)}")

        # Deduplicate: prefer higher confidence
        addr_best: dict[str, dict] = {}
        for r in results:
            addr = r["address"]
            if addr not in addr_best or conf_rank[r["confidence"]] > conf_rank[addr_best[addr]["confidence"]]:
                addr_best[addr] = r

        deduped = sorted(addr_best.values(), key=lambda r: int(r["address"], 16))
        print(f"[deduped] {len(deduped)}")

        # Write CSV
        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(
                fh,
                fieldnames=["address", "name", "class_name", "confidence", "evidence"],
            )
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
