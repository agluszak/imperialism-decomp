#!/usr/bin/env python3
"""
Infer return types and calling conventions for functions with undefined return type
by decompiling each function and parsing the decompiler's inferred signature.

The Ghidra decompiler infers return types and parameters even when the stored
signature says ``undefined funcName(void)`` and ``cc=unknown``.  This command
extracts those inferred types and generates a signature CSV that can be applied
with ``apply_signatures_from_csv``.

Output CSV columns:
  address, calling_convention, return_type, params, decompiler_signature

Usage:
  uv run impk infer_return_type_from_decomp \
    --out-csv tmp_decomp/inferred_return_types.csv \
    [--max-functions N]
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


# Map Ghidra display types to CSV-friendly short names
_TYPE_NORMALIZE = {
    "undefined": "void",
    "undefined1": "byte",
    "undefined2": "short",
    "undefined4": "int",
    "undefined8": "longlong",
    "uint": "uint",
    "int": "int",
    "void": "void",
    "bool": "bool",
    "byte": "byte",
    "char": "char",
    "short": "short",
    "ushort": "ushort",
    "long": "int",
    "ulong": "uint",
    "BOOL": "int",
}


def _normalize_type(ghidra_type: str) -> str:
    """Convert a Ghidra display type to a CSV-friendly short name."""
    t = ghidra_type.strip()
    # Handle pointer types
    ptr_depth = 0
    while t.endswith(" *") or t.endswith("*"):
        ptr_depth += 1
        t = t.rstrip("*").rstrip()
    base = _TYPE_NORMALIZE.get(t, t)
    return base + "*" * ptr_depth


def _extract_decomp_signature(c_code: str, func_name: str):
    """Parse decompiler C output to extract return type and params.

    The decompiler emits a function header like::

        void __thiscall ClassName::FuncName(ClassName *this, int param_2)

    or for unknown cc::

        void PostCommand100ToMainWindow(void)

    Returns (return_type, cc_hint, param_list) or None on failure.
    """
    # Find the function header - look for the function name followed by opening paren
    # The header may span multiple lines due to long signatures
    # Pattern: <return_type> [<cc>] [<ns>::]<name>(<params>)
    escaped_name = re.escape(func_name)
    # Join lines to handle multi-line signatures
    flat = " ".join(c_code.split("\n"))

    # Try to match: <rettype> [__cc] [Ns::]FuncName(<params>)
    pattern = (
        r'(\w[\w\s\*]*?)\s+'  # return type (greedy but stops at cc/name)
        r'(?:(__\w+)\s+)?'     # optional calling convention
        r'(?:\w+::)?'          # optional namespace::
        + escaped_name +
        r'\s*\(([^)]*)\)'     # params in parens
    )
    m = re.search(pattern, flat)
    if not m:
        return None

    ret_type_raw = m.group(1).strip()
    cc_hint = m.group(2) or ""
    params_raw = m.group(3).strip()

    # Clean up return type: remove leading comments, annotations
    # The decompiler may emit "/* ... */ void" before the return type
    ret_type_raw = re.sub(r'/\*.*?\*/', '', ret_type_raw).strip()
    # Take only the last type token(s) in case of leftover comment text
    # e.g., "some comment text void" -> "void"
    tokens = ret_type_raw.split()
    if len(tokens) > 1:
        # Check if last token(s) form a valid type
        for i in range(len(tokens)):
            candidate = " ".join(tokens[i:])
            if candidate.replace("*", "").replace(" ", "") in _TYPE_NORMALIZE or "*" in candidate:
                ret_type_raw = candidate
                break

    ret_type = _normalize_type(ret_type_raw)

    # Parse params
    param_list = []
    if params_raw and params_raw != "void":
        for part in params_raw.split(","):
            part = part.strip()
            if not part:
                continue
            # Split "TypeName paramName" - last word is name, rest is type
            # Handle pointer types: "void * param_1"
            words = part.split()
            if len(words) >= 2:
                param_name = words[-1]
                param_type = " ".join(words[:-1])
                param_type = _normalize_type(param_type)
                param_list.append((param_name, param_type))
            elif len(words) == 1:
                # Just a type with no name (e.g., "void")
                if words[0].lower() == "void":
                    continue
                param_list.append((f"param_{len(param_list)+1}", _normalize_type(words[0])))

    return ret_type, cc_hint, param_list


def main() -> int:
    ap = argparse.ArgumentParser()
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
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()

        ifc = DecompInterface()
        ifc.openProgram(program)

        results = []
        count = 0
        skipped = 0
        decomp_fail = 0

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            addr_int = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            fn_name = fn.getName()

            # Only process functions with undefined return type
            ret_type_name = fn.getReturnType().getName()
            if not ret_type_name.startswith("undefined"):
                continue

            if args.max_functions and count >= args.max_functions:
                skipped += 1
                continue

            count += 1

            # Decompile
            res = ifc.decompileFunction(fn, 20, None)
            if not res or not res.decompileCompleted():
                decomp_fail += 1
                continue
            dc = res.getDecompiledFunction()
            if dc is None:
                decomp_fail += 1
                continue
            c_code = str(dc.getC())
            if not c_code:
                decomp_fail += 1
                continue

            # Extract signature from decompiled output
            parsed = _extract_decomp_signature(c_code, fn_name)
            if parsed is None:
                decomp_fail += 1
                continue

            ret_type, cc_hint, param_list = parsed

            # Skip if decompiler also says undefined/void with no useful info
            # (we want to find functions where the decompiler infers something useful)
            stored_cc = fn.getCallingConventionName()

            # Build params string for CSV
            params_csv = ";".join(f"{name}:{typ}" for name, typ in param_list) if param_list else ""

            # Determine the best calling convention to use
            if cc_hint:
                cc_out = cc_hint
            elif stored_cc and stored_cc != "unknown":
                cc_out = stored_cc
            else:
                # Infer from params: if first param looks like a this pointer, use __thiscall
                if param_list and param_list[0][0] in ("this", "pThis", "param_1") and "*" in param_list[0][1]:
                    cc_out = "__thiscall"
                else:
                    cc_out = "__cdecl"

            results.append({
                "address": f"0x{addr_int:08x}",
                "calling_convention": cc_out,
                "return_type": ret_type,
                "params": params_csv,
                "decompiler_signature": c_code.split("\n{")[0].strip()[-200:] if "{" in c_code else "",
                "stored_cc": stored_cc,
                "stored_ret": ret_type_name,
            })

            if count % 500 == 0:
                print(f"  [progress] decompiled {count}, results={len(results)}, decomp_fail={decomp_fail}")

        ifc.dispose()

        print(f"[scan] decompiled={count} results={len(results)} decomp_fail={decomp_fail} skipped={skipped}")

        # Stats
        ret_dist = Counter(r["return_type"] for r in results)
        cc_dist = Counter(r["calling_convention"] for r in results)
        print(f"\n[return types]")
        for rt, cnt in ret_dist.most_common(20):
            print(f"  {rt}: {cnt}")
        print(f"\n[calling conventions]")
        for cc, cnt in cc_dist.most_common():
            print(f"  {cc}: {cnt}")

        # Write CSV
        fieldnames = ["address", "calling_convention", "return_type", "params",
                       "decompiler_signature", "stored_cc", "stored_ret"]
        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(results)

    print(f"\n[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
