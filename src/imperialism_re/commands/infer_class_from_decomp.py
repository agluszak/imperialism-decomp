#!/usr/bin/env python3
"""
Infer class membership for Global __thiscall functions by decompiling them.

Signals used (in priority order):
  1. Vtable assignment: ``*(int *)this = <vtable_addr>`` → look up vtable owner class
  2. Calls to class-namespaced methods on ``this`` (param_1 passed as first arg)
  3. Field access patterns matching known struct layouts

Output CSV columns:
  address, class_name, confidence, evidence

Usage:
  uv run impk infer_class_from_decomp --out-csv tmp_decomp/class_infer.csv [--apply-limit N]
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.commands.mine_struct_field_access import _extract_field_accesses


def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 20, None)
    if not res or not res.decompileCompleted():
        return ""
    dc = res.getDecompiledFunction()
    if dc is None:
        return ""
    return str(dc.getC())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-functions", type=int, default=0, help="Limit (0=all)")
    ap.add_argument("--fp-min-match-high", type=int, default=5,
        help="Min matching offsets for high-confidence field fingerprint")
    ap.add_argument("--fp-min-match-medium", type=int, default=3,
        help="Min matching offsets for medium-confidence field fingerprint")
    ap.add_argument("--fp-base-cutoff", type=int, default=0x40,
        help="Exclude offsets below this value (base-class TControl/TView fields)")
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
        dtm = program.getDataTypeManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()
        af = program.getAddressFactory().getDefaultAddressSpace()

        # Build class namespace map
        class_names = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            cls = it_cls.next()
            class_names.add(cls.getName())

        # Build vtable_addr -> class_name mapping from labeled data
        # Vtable labels follow pattern: g_vtbl<ClassName>* or are in class struct paths
        vtable_to_class = {}
        sym_it = st.getAllSymbols(False)
        while sym_it.hasNext():
            sym = sym_it.next()
            name = sym.getName()
            if not name:
                continue
            # Match g_vtbl<ClassName> patterns
            if name.startswith("g_vtbl"):
                # Extract class name: g_vtbl<ClassName>_SlotNN or g_vtbl<ClassName>
                rest = name[6:]  # strip g_vtbl
                # Find the class name by matching against known classes
                for cls in sorted(class_names, key=len, reverse=True):
                    if rest.startswith(cls):
                        addr = sym.getAddress()
                        if not addr.isExternalAddress():
                            vtable_to_class[int(str(addr), 16)] = cls
                        break

        # Also detect vtable addresses from PTR_* labels pointing to class functions
        # and from constructor patterns

        print(f"[init] vtable_to_class entries: {len(vtable_to_class)}")
        print(f"[init] known classes: {len(class_names)}")

        # Build function_name -> class_name map for callee analysis
        fn_name_to_class = {}
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            ns_name = ns.getName()
            if ns_name in class_names:
                fn_name_to_class[fn.getName()] = ns_name

        print(f"[init] class-namespaced function names: {len(fn_name_to_class)}")

        # Build field-offset fingerprints for Signal 3
        from ghidra.program.model.data import Structure
        class_offset_fingerprints = {}
        it_cls2 = st.getClassNamespaces()
        while it_cls2.hasNext():
            cls_ns = it_cls2.next()
            cls_name = cls_ns.getName()
            for cat in ["/imperialism/classes/", "/", "/imperialism/types/"]:
                dt = dtm.getDataType(f"{cat}{cls_name}")
                if dt is not None and isinstance(dt, Structure):
                    named_offsets = set()
                    for comp in dt.getComponents():
                        fn = comp.getFieldName()
                        if fn and not fn.startswith("field_0x"):
                            named_offsets.add(int(comp.getOffset()))
                    if len(named_offsets) >= 3:
                        class_offset_fingerprints[cls_name] = frozenset(named_offsets)
                    break
        print(f"[init] field fingerprints (>=3 named fields): {len(class_offset_fingerprints)}")

        # Set up decompiler
        ifc = DecompInterface()
        ifc.openProgram(program)

        # Iterate Global __thiscall functions
        results = []
        count = 0
        total_global_thiscall = 0

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is not None and ns != global_ns:
                continue
            cc = fn.getCallingConventionName()
            if cc != "__thiscall":
                continue

            # Check if first param is void*
            params = list(fn.getParameters())
            if not params:
                continue
            p0_type = params[0].getDataType().getName()
            if "void *" not in p0_type and p0_type != "void *":
                continue

            total_global_thiscall += 1

            if args.max_functions and count >= args.max_functions:
                continue  # still count total but don't decompile

            count += 1
            addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            fn_name = fn.getName()

            # Decompile
            c_code = decompile_text(ifc, fn)
            if not c_code:
                continue

            # Signal 1: Vtable assignment pattern
            # Look for: *(int *)param_1 = 0xNNNNNNNN  (vtable base assignment)
            # or: *(undefined4 *)param_1 = 0xNNNNNNNN
            vtable_hits = re.findall(
                r'\*\s*\([^)]*\)\s*(?:param_1|this)\s*=\s*(0x[0-9a-fA-F]+)',
                c_code
            )
            for vhit in vtable_hits:
                try:
                    vaddr = int(vhit, 16)
                    if vaddr in vtable_to_class:
                        results.append({
                            "address": f"0x{addr_int:08x}",
                            "name": fn_name,
                            "class_name": vtable_to_class[vaddr],
                            "confidence": "high",
                            "evidence": f"vtable_assign_{vhit}",
                        })
                except ValueError:
                    pass

            # Signal 2: Calls to class-namespaced methods
            # Look for function calls where param_1/this is passed
            # Pattern: ClassName::MethodName(param_1, ...) or MethodName(param_1, ...)
            # In decompiled C, class methods appear as their plain name
            callee_classes = Counter()
            # Find all function calls in the decompiled body
            call_pattern = re.findall(r'(\w+)\s*\(', c_code)
            for callee_name in call_pattern:
                if callee_name in fn_name_to_class:
                    callee_classes[fn_name_to_class[callee_name]] += 1

            if callee_classes:
                top_cls, top_count = callee_classes.most_common(1)[0]
                total_calls = sum(callee_classes.values())
                if top_count >= 2 or (top_count == 1 and len(callee_classes) == 1):
                    # Check if already have a vtable hit
                    already = any(
                        r["address"] == f"0x{addr_int:08x}" for r in results
                    )
                    if not already:
                        results.append({
                            "address": f"0x{addr_int:08x}",
                            "name": fn_name,
                            "class_name": top_cls,
                            "confidence": "medium" if top_count >= 2 else "low",
                            "evidence": f"callee_votes_{top_cls}={top_count}_of_{total_calls}",
                        })

            # Signal 3: Field-offset fingerprinting
            already_assigned = any(r["address"] == f"0x{addr_int:08x}" for r in results)
            if not already_assigned and class_offset_fingerprints:
                accesses = _extract_field_accesses(c_code)
                accessed_offsets = frozenset(
                    o for o, _s, _t in accesses if o >= args.fp_base_cutoff
                )
                if len(accessed_offsets) >= 3:
                    best_cls, best_hits, best_ratio = None, 0, 0.0
                    for cls_name, fp in class_offset_fingerprints.items():
                        fp_disc = frozenset(o for o in fp if o >= args.fp_base_cutoff)
                        if not fp_disc:
                            continue
                        hits = len(accessed_offsets & fp_disc)
                        if hits == 0:
                            continue
                        ratio = hits / len(accessed_offsets)
                        score = hits * ratio
                        if score > best_hits * best_ratio or (
                            score == best_hits * best_ratio and hits > best_hits
                        ):
                            best_cls, best_hits, best_ratio = cls_name, hits, ratio
                    if best_cls:
                        if best_hits >= args.fp_min_match_high and best_ratio >= 0.4:
                            conf = "high"
                        elif best_hits >= args.fp_min_match_medium and best_ratio >= 0.25:
                            conf = "medium"
                        else:
                            conf = None
                        if conf:
                            results.append({
                                "address": f"0x{addr_int:08x}",
                                "name": fn_name,
                                "class_name": best_cls,
                                "confidence": conf,
                                "evidence": f"field_fp_{best_cls}=match{best_hits}_ratio{best_ratio:.2f}",
                            })

            if count % 200 == 0:
                print(f"  [progress] decompiled {count}, results so far: {len(results)}")

        ifc.dispose()

        print(f"[scan] total Global __thiscall void*: {total_global_thiscall}")
        print(f"[scan] decompiled: {count}")
        print(f"[results] total: {len(results)}")

        # Deduplicate: if same address has vtable hit, prefer that over callee
        addr_best = {}
        for r in results:
            addr = r["address"]
            if addr not in addr_best or r["confidence"] == "high":
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
