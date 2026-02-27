#!/usr/bin/env python3
"""
Resolve cc=unknown functions via thunk-chain propagation and decompiler inference.

Two-phase approach:
  Phase 1: Iteratively propagate known CCs through single-JMP thunk chains.
  Phase 2: Decompile remaining unknowns and extract CC from the decompiler header.

Output CSV columns:
  address, calling_convention, return_type, phase, evidence

Compatible with ``apply_return_type_and_cc`` (extra columns ignored by DictReader).

Usage:
  uv run impk resolve_unknown_cc --out-csv tmp_decomp/resolved_cc.csv
  uv run impk apply_return_type_and_cc tmp_decomp/resolved_cc.csv --apply
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.ghidra_session import open_program


FIELDNAMES = [
    "address",
    "calling_convention",
    "return_type",
    "phase",
    "evidence",
]


def _is_single_jmp_thunk(fn, listing):
    """Return the JMP target function if *fn* is a single-JMP thunk, else None."""
    body = fn.getBody()
    if body is None:
        return None
    ins_iter = listing.getInstructions(body, True)
    ins_list = []
    while ins_iter.hasNext():
        ins_list.append(ins_iter.next())
        if len(ins_list) > 1:
            return None
    if len(ins_list) != 1:
        return None
    i0 = ins_list[0]
    text = str(i0)
    if not text.startswith("JMP "):
        return None
    refs = i0.getReferencesFrom()
    for ref in refs:
        tgt = ref.getToAddress()
        if tgt.isExternalAddress():
            continue
        fm = fn.getProgram().getFunctionManager()
        tf = fm.getFunctionAt(tgt)
        if tf is None:
            continue
        if tf.getEntryPoint().isExternalAddress():
            continue
        if int(str(tf.getEntryPoint()), 16) == int(str(tgt), 16):
            return tf
    return None


def _extract_cc_from_decomp(c_code: str, func_name: str) -> str | None:
    """Parse decompiler C output to extract calling convention hint."""
    escaped_name = re.escape(func_name)
    flat = " ".join(c_code.split("\n"))
    pattern = (
        r'(\w[\w\s\*]*?)\s+'
        r'(?:(__\w+)\s+)?'
        r'(?:\w+::)?'
        + escaped_name
        + r'\s*\(([^)]*)\)'
    )
    m = re.search(pattern, flat)
    if not m:
        return None
    cc_hint = m.group(2) or ""
    params_raw = m.group(3).strip()
    if cc_hint:
        return cc_hint
    # Fallback heuristic: if first param is a this-like pointer, __thiscall
    if params_raw and params_raw != "void":
        first_param = params_raw.split(",")[0].strip()
        words = first_param.split()
        if len(words) >= 2:
            param_name = words[-1]
            param_type = " ".join(words[:-1])
            if param_name in ("this", "pThis") and "*" in param_type:
                return "__thiscall"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Resolve cc=unknown via thunk-chain propagation + decompiler inference.",
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument(
        "--max-iterations",
        type=int,
        default=20,
        help="Max thunk-chain propagation iterations (default 20)",
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
        fm = program.getFunctionManager()
        listing = program.getListing()

        # --- Collect all cc=unknown functions ---
        unknown_fns: dict[int, object] = {}  # addr -> function
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            if fn.getCallingConventionName() == "unknown":
                addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
                unknown_fns[addr_int] = fn

        print(f"[init] cc=unknown functions: {len(unknown_fns)}")

        # --- Build thunk map for unknown functions ---
        thunk_targets: dict[int, int] = {}  # thunk_addr -> target_addr
        for addr_int, fn in unknown_fns.items():
            tgt = _is_single_jmp_thunk(fn, listing)
            if tgt is not None:
                tgt_addr = tgt.getEntryPoint().getOffset() & 0xFFFFFFFF
                thunk_targets[addr_int] = tgt_addr

        print(f"[init] thunk pairs among unknowns: {len(thunk_targets)}")

        # --- Phase 1: Iterative thunk-chain CC propagation ---
        results: dict[int, dict] = {}  # addr -> row dict
        remaining = set(unknown_fns.keys())

        for iteration in range(1, args.max_iterations + 1):
            resolved_this_round = 0
            for addr_int in list(remaining):
                if addr_int not in thunk_targets:
                    continue
                tgt_addr = thunk_targets[addr_int]

                # Check if target has known CC (either already known or resolved earlier)
                tgt_cc = None
                if tgt_addr in results:
                    tgt_cc = results[tgt_addr]["calling_convention"]
                else:
                    tgt_fn = fm.getFunctionAt(
                        program.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(f"0x{tgt_addr:08x}")
                    )
                    if tgt_fn is not None:
                        cc = tgt_fn.getCallingConventionName()
                        if cc != "unknown":
                            tgt_cc = cc

                if tgt_cc is None:
                    continue

                fn = unknown_fns[addr_int]
                ret_type = fn.getReturnType().getName()
                if ret_type.startswith("undefined"):
                    ret_type = "void"

                results[addr_int] = {
                    "address": f"0x{addr_int:08x}",
                    "calling_convention": tgt_cc,
                    "return_type": ret_type,
                    "phase": "thunk_propagation",
                    "evidence": f"iter={iteration}_target=0x{tgt_addr:08x}",
                }
                remaining.discard(addr_int)
                resolved_this_round += 1

            print(f"  [phase1] iteration {iteration}: resolved {resolved_this_round}")
            if resolved_this_round == 0:
                break

        phase1_count = len(results)
        print(f"[phase1] total resolved via thunk propagation: {phase1_count}")

        # --- Phase 2: Decompiler inference for remaining ---
        still_unknown = [addr for addr in remaining if addr not in results]
        print(f"[phase2] remaining to decompile: {len(still_unknown)}")

        if still_unknown:
            from ghidra.app.decompiler import DecompInterface

            ifc = DecompInterface()
            ifc.openProgram(program)

            decomp_ok = 0
            decomp_fail = 0
            for addr_int in still_unknown:
                fn = unknown_fns[addr_int]
                fn_name = fn.getName()

                res = ifc.decompileFunction(fn, 20, None)
                if not res or not res.decompileCompleted():
                    decomp_fail += 1
                    # Fallback: check params for this hint
                    params = list(fn.getParameters())
                    if params:
                        p0_name = params[0].getName()
                        p0_type = params[0].getDataType().getName()
                        if p0_name in ("this", "pThis") and "*" in p0_type:
                            cc_out = "__thiscall"
                        else:
                            cc_out = "__cdecl"
                    else:
                        cc_out = "__cdecl"

                    ret_type = fn.getReturnType().getName()
                    if ret_type.startswith("undefined"):
                        ret_type = "void"

                    results[addr_int] = {
                        "address": f"0x{addr_int:08x}",
                        "calling_convention": cc_out,
                        "return_type": ret_type,
                        "phase": "param_fallback",
                        "evidence": "decomp_failed",
                    }
                    continue

                dc = res.getDecompiledFunction()
                if dc is None:
                    decomp_fail += 1
                    continue
                c_code = str(dc.getC())
                if not c_code:
                    decomp_fail += 1
                    continue

                cc_hint = _extract_cc_from_decomp(c_code, fn_name)
                if cc_hint:
                    cc_out = cc_hint
                    evidence = f"decomp_header={cc_hint}"
                else:
                    # Fallback: check stored params
                    params = list(fn.getParameters())
                    if params:
                        p0_name = params[0].getName()
                        p0_type = params[0].getDataType().getName()
                        if p0_name in ("this", "pThis") and "*" in p0_type:
                            cc_out = "__thiscall"
                            evidence = "decomp_no_cc_but_this_param"
                        else:
                            cc_out = "__cdecl"
                            evidence = "decomp_no_cc_default_cdecl"
                    else:
                        cc_out = "__cdecl"
                        evidence = "decomp_no_cc_no_params"

                ret_type = fn.getReturnType().getName()
                if ret_type.startswith("undefined"):
                    ret_type = "void"

                results[addr_int] = {
                    "address": f"0x{addr_int:08x}",
                    "calling_convention": cc_out,
                    "return_type": ret_type,
                    "phase": "decomp_inference",
                    "evidence": evidence,
                }
                decomp_ok += 1

            ifc.dispose()
            print(f"[phase2] decomp_ok={decomp_ok} decomp_fail={decomp_fail}")

        # --- Output ---
        rows = sorted(results.values(), key=lambda r: int(r["address"], 16))
        write_csv_rows(out_csv, rows, FIELDNAMES)

        # Stats
        phase_dist = Counter(r["phase"] for r in rows)
        cc_dist = Counter(r["calling_convention"] for r in rows)
        print(f"\n[result] total resolved: {len(rows)} of {len(unknown_fns)}")
        print(f"[phases] {dict(phase_dist)}")
        print(f"[cc distribution] {dict(cc_dist)}")
        print(f"[saved] {out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
