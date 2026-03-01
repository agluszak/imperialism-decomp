#!/usr/bin/env python3
"""
Infer class membership for Global __thiscall functions via SymbolicPropogator.

Uses Ghidra's SymbolicPropogator to perform constant propagation along the CFG,
then checks every instruction that stores to [param0] or [param0+offset] for a
propagated constant value that matches a known vtable address.

This catches cases that Pcode SSA misses:
  - Constants computed across basic blocks (mov eax, vtbl_base; add eax, offset)
  - Register-relative values resolved through arithmetic
  - Values loaded from read-only memory (constant tables)

Output CSV columns:
  address, name, class_name, confidence, evidence

Usage:
  uv run impk infer_class_from_constprop --out-csv tmp_decomp/class_infer_constprop.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Infer class membership for Global __thiscall functions "
        "via SymbolicPropogator constant propagation.",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-functions", type=int, default=0, help="Limit (0=all)")
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
        from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
        from ghidra.program.util import SymbolicPropogator
        from ghidra.util.task import ConsoleTaskMonitor

        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()
        listing = program.getListing()
        monitor = ConsoleTaskMonitor()

        # --- Build class namespace set ---
        class_names: set[str] = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            cls = it_cls.next()
            class_names.add(cls.getName())

        # --- Build vtable_addr -> class_name mapping ---
        vtable_to_class: dict[int, str] = {}
        sym_it = st.getAllSymbols(False)
        while sym_it.hasNext():
            sym = sym_it.next()
            name = sym.getName()
            if not name:
                continue
            if name.startswith("g_vtbl"):
                rest = name[6:]
                for cls in sorted(class_names, key=len, reverse=True):
                    if rest.startswith(cls):
                        addr = sym.getAddress()
                        if not addr.isExternalAddress():
                            vtable_to_class[int(str(addr), 16)] = cls
                        break

        print(f"[init] vtable_to_class entries: {len(vtable_to_class)}")
        print(f"[init] known classes: {len(class_names)}")

        # --- Collect candidates (Global __thiscall void*) ---
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

        # --- Per-candidate SymbolicPropogator analysis ---
        # SymbolicPropogator.flowConstants() writes internally to the program
        # context, so it requires an open transaction.  We open one for the
        # whole scan and roll it back at the end (read-only command).
        tx = program.startTransaction("constprop inference (read-only, will rollback)")
        results = []
        count = 0
        sp_fail = 0

        try:
            for fn in candidates:
                if args.max_functions and count >= args.max_functions:
                    break
                count += 1

                addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                fn_name = fn.getName()

                # Identify param0 register (ECX for __thiscall on x86)
                p0_reg = None
                params = fn.getParameters()
                if params and len(params) > 0:
                    p0_reg = params[0].getRegister()
                if p0_reg is None:
                    # __thiscall on x86: ECX
                    p0_reg = program.getLanguage().getRegister("ECX")
                if p0_reg is None:
                    continue

                # Run SymbolicPropogator
                try:
                    symeval = SymbolicPropogator(program)
                    evaluator = ConstantPropagationContextEvaluator(monitor, True)
                    symeval.flowConstants(
                        fn.getEntryPoint(), fn.getBody(), evaluator, True, monitor,
                    )
                except Exception as ex:
                    sp_fail += 1
                    if sp_fail <= 5:
                        print(f"  [sp-fail] 0x{addr_int:08x} {fn_name} err={ex}")
                    continue

                # Scan instructions in function body for stores to [param0+offset]
                # We look for MOV [reg], <value> where reg traces to param0
                vtable_hits: dict[str, int] = {}  # class_name -> count
                body = fn.getBody()
                inst_iter = listing.getInstructions(body, True)
                while inst_iter.hasNext():
                    inst = inst_iter.next()
                    inst_addr = inst.getAddress()
                    mnemonic = str(inst.getMnemonicString()).upper()

                    # We're interested in MOV instructions that store to memory
                    if mnemonic != "MOV":
                        continue

                    n_ops = inst.getNumOperands()
                    if n_ops < 2:
                        continue

                    # Query propagated register values at this instruction.
                    # For `MOV [ecx], eax` the source is operand 1.
                    # We check all register operands for known vtable values.
                    for op_idx in range(n_ops):
                        obj = inst.getOpObjects(op_idx)
                        if obj is None:
                            continue
                        for o in obj:
                            try:
                                reg_name = str(o.getName()) if hasattr(o, "getName") else None
                                if reg_name is None:
                                    continue
                                val = symeval.getRegisterValue(inst_addr, o)
                                if val is None:
                                    continue
                                if val.isRegisterRelativeValue():
                                    continue
                                raw_val = val.getValue()
                                if raw_val is None:
                                    continue
                                vtable_addr = int(str(raw_val)) & 0xFFFFFFFF
                                if vtable_addr in vtable_to_class:
                                    cls = vtable_to_class[vtable_addr]
                                    vtable_hits[cls] = vtable_hits.get(cls, 0) + 1
                            except Exception:
                                continue

                if not vtable_hits:
                    continue

                # Pick class with most hits (last vtable write = own class in ctors)
                top_cls = max(vtable_hits, key=vtable_hits.get)
                top_count = vtable_hits[top_cls]

                confidence = "high" if top_count >= 1 else "medium"
                evidence = (
                    f"constprop_vtable_{top_cls}="
                    f"hits{top_count}_classes{len(vtable_hits)}"
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
        finally:
            # Rollback — this is a reader command, no changes should persist
            program.endTransaction(tx, False)

        print(f"[scan] analyzed: {count} of {len(candidates)}")
        print(f"[scan] sp_fail: {sp_fail}")
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
        print("[top classes]")
        for cls, cnt in cls_dist.most_common(15):
            print(f"  {cls}: {cnt}")

    print(f"\n[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
