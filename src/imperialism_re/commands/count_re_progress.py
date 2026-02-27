#!/usr/bin/env python3
"""
Quick reverse-engineering progress counters.

Usage:
  uv run impk count_re_progress [--project-root <path>]
"""

from __future__ import annotations

import argparse
import re

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
RX_DEFAULT = re.compile(r"^(FUN_|thunk_FUN_)")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    with open_program(root) as program:
        fm = program.getFunctionManager()
        st = program.getSymbolTable()

        total = renamed = default_named = 0
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            total += 1
            if RX_DEFAULT.match(f.getName()):
                default_named += 1
            else:
                renamed += 1

        class_desc = vtbl = tname = 0
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            n = sit.next().getName()
            if n.startswith("g_pClassDescT"):
                class_desc += 1
            if n.startswith("g_vtblT"):
                # Count canonical class vtable roots only, not per-slot/auxiliary aliases.
                if "_Slot" in n or "Candidate_" in n or "Family_" in n:
                    continue
                vtbl += 1
            if n.startswith("g_szTypeNameT"):
                tname += 1

    print("total_functions", total)
    print("renamed_functions", renamed)
    print("default_fun_or_thunk_fun", default_named)
    print("class_desc_count", class_desc)
    print("vtbl_count", vtbl)
    print("type_name_count", tname)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
