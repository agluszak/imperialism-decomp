#!/usr/bin/env python3
"""
Infer class membership for Global __thiscall functions via global data references.

Builds a global_addr → class_name map from all symbols in the global data range
(vtables like ``g_vtblTFoo`` → ``TFoo``, class-namespaced symbols, PTR entries
under class namespaces), then checks which class-associated globals each candidate
function references in its instructions.

Output CSV columns:
  address, name, class_name, confidence, evidence

Usage:
  uv run impk infer_class_from_indirect_refs \
    --out-csv tmp_decomp/indirect_ref_class_infer.csv
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program


# Pattern to extract class name from vtable symbol names
_VTBL_PATTERN = re.compile(r"^(?:g_)?vtbl(\w+)")
# Pattern to extract class name from class-prefixed globals (e.g., g_TFoo_Something)
_CLASS_PREFIX_PATTERN = re.compile(r"^g_(T[A-Z]\w+?)_")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Infer class membership for Global __thiscall functions "
        "via global data access patterns (vtables, class-namespaced symbols).",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-functions", type=int, default=0, help="Limit (0=all)")
    ap.add_argument(
        "--min-globals",
        type=int,
        default=1,
        help="Minimum class-associated globals accessed to emit (default 1)",
    )
    ap.add_argument(
        "--min-ratio",
        type=float,
        default=0.67,
        help="Minimum ratio of top class votes for medium confidence (default 0.67)",
    )
    ap.add_argument(
        "--addr-min",
        default="0x00648000",
        help="Global data range minimum (hex, default 0x00648000)",
    )
    ap.add_argument(
        "--addr-max",
        default="0x006BFFFF",
        help="Global data range maximum (hex, default 0x006BFFFF)",
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

    global_addr_min = int(args.addr_min, 16)
    global_addr_max = int(args.addr_max, 16)

    with open_program(root) as program:
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        listing = program.getListing()
        global_ns = program.getGlobalNamespace()

        # --- Step 1: Build global_addr → class_name map ---
        # Scan all symbols in the global data range
        global_class_map: dict[int, str] = {}

        # Collect known class namespace names
        class_names = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            cls = it_cls.next()
            class_names.add(cls.getName())

        # Iterate all symbols in range
        af = program.getAddressFactory().getDefaultAddressSpace()
        addr_start = af.getAddress(f"0x{global_addr_min:08x}")
        addr_end = af.getAddress(f"0x{global_addr_max:08x}")
        sym_iter = st.getSymbolIterator(addr_start, True)
        while sym_iter.hasNext():
            sym = sym_iter.next()
            addr = sym.getAddress()
            offset = addr.getOffset() & 0xFFFFFFFF
            if offset > global_addr_max:
                break

            name = sym.getName()
            ns = sym.getParentNamespace()
            ns_name = ns.getName() if ns is not None and ns != global_ns else "Global"

            # Source 1: symbol is in a class namespace
            if ns_name in class_names:
                global_class_map[offset] = ns_name
                continue

            # Source 2: vtable name pattern (g_vtblTFoo → TFoo)
            m = _VTBL_PATTERN.match(name)
            if m:
                vtbl_cls = m.group(1)
                if vtbl_cls in class_names:
                    global_class_map[offset] = vtbl_cls
                    continue

            # Source 3: class-prefixed global name (g_TFoo_Something → TFoo)
            m = _CLASS_PREFIX_PATTERN.match(name)
            if m:
                prefix_cls = m.group(1)
                if prefix_cls in class_names:
                    global_class_map[offset] = prefix_cls
                    continue

        print(f"[init] known classes: {len(class_names)}")
        print(f"[init] globals mapped to classes: {len(global_class_map)}")

        # Show class distribution in the map
        map_cls_dist = Counter(global_class_map.values())
        print(f"[init] top class-mapped globals:")
        for cls, cnt in map_cls_dist.most_common(10):
            print(f"  {cls}: {cnt}")

        # --- Step 2: Collect candidates: Global __thiscall with void* this ---
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

        # --- Step 3: Per-candidate instruction scan ---
        results = []
        count = 0

        for fn in candidates:
            if args.max_functions and count >= args.max_functions:
                break
            count += 1

            addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            fn_name = fn.getName()

            class_votes: Counter = Counter()
            total_global_refs = 0
            body = fn.getBody()
            if body is None:
                continue

            ins_iter = listing.getInstructions(body, True)
            while ins_iter.hasNext():
                ins = ins_iter.next()
                refs = ins.getReferencesFrom()
                for ref in refs:
                    tgt = ref.getToAddress()
                    if tgt.isExternalAddress():
                        continue
                    tgt_offset = tgt.getOffset() & 0xFFFFFFFF
                    if tgt_offset < global_addr_min or tgt_offset > global_addr_max:
                        continue
                    total_global_refs += 1
                    cls = global_class_map.get(tgt_offset)
                    if cls:
                        class_votes[cls] += 1

            classified_count = sum(class_votes.values())
            if classified_count < args.min_globals or not class_votes:
                continue

            top_cls, top_count = class_votes.most_common(1)[0]
            ratio = top_count / classified_count

            if ratio == 1.0:
                confidence = "high"
            elif ratio >= args.min_ratio:
                confidence = "medium"
            else:
                confidence = "low"

            if conf_rank[confidence] < conf_filter_rank:
                continue

            evidence = (
                f"globals_{top_cls}={top_count}_of_{classified_count}"
                f"_total_grefs={total_global_refs}"
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
        fieldnames = ["address", "name", "class_name", "confidence", "evidence"]
        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            import csv

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
