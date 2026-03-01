#!/usr/bin/env python3
"""
Fallback: propose macOS method names for unnamed Windows class functions via signature
shape matching.

For classes where vtable extraction failed or is unavailable, use heuristic matching:
  1. Load macos_class_methods.csv → class → [method_names]
  2. For each Windows class namespace:
     - Collect already-named methods (excluding FUN_*, thunk_FUN_*, Cluster_*)
     - Compute missing = macOS methods − already-named Windows method names
     - Collect unnamed functions in this class namespace (FUN_*, etc.)
     - Skip if len(unnamed) > len(missing) × max_ambiguity_ratio (too ambiguous)
     - For each unnamed Windows function, decompile to get param count and return type
     - For each missing macOS method, get param count from CSV params column
     - Score each (unnamed_fn, macos_method) pair by parameter count similarity
     - Emit the top-scoring match per unnamed function as a low-confidence candidate

Output CSV: address, class_name, proposed_name, confidence, evidence

Usage:
  uv run impk propose_macos_vocabulary_names \\
      --out-csv tmp_decomp/macos_vocabulary_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.decompiler import (
    create_configured_decompiler,
    decompile_function,
)
from imperialism_re.core.ghidra_session import open_program


def _is_generic_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or (name.startswith("thunk_") and "FUN_" in name)
    )


def _count_params_from_str(params_str: str) -> int:
    """Count comma-separated params in a Cfront params string like '(ptr,int,int)'."""
    params_str = params_str.strip("() ")
    if not params_str:
        return 0
    return len([p for p in params_str.split(",") if p.strip()])


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Propose macOS method names for unnamed Windows class functions.",
    )
    ap.add_argument(
        "--macos-csv",
        default="tmp_decomp/macos_class_methods.csv",
        help="macOS class methods CSV (default: tmp_decomp/macos_class_methods.csv)",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/macos_vocabulary_candidates.csv",
        help="Output candidates CSV (default: tmp_decomp/macos_vocabulary_candidates.csv)",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Comma-separated class filter (default: all)",
    )
    ap.add_argument(
        "--max-ambiguity-ratio",
        type=float,
        default=2.0,
        help="Skip class if len(unnamed) > len(missing) × ratio (default: 2.0)",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    macos_csv_path = Path(args.macos_csv)
    if not macos_csv_path.is_absolute():
        macos_csv_path = root / macos_csv_path
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    class_filter: set[str] = {x.strip() for x in args.classes.split(",") if x.strip()}

    # Load macOS method names and param counts per class
    # macos_class_info[class] = list of (method_name, param_count)
    macos_class_info: dict[str, list[tuple[str, int]]] = defaultdict(list)
    with macos_csv_path.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cls = row.get("class", "").strip()
            method = row.get("method", "").strip()
            params_str = row.get("params", "").strip()
            if not cls or not method:
                continue
            if class_filter and cls not in class_filter:
                continue
            param_count = _count_params_from_str(params_str)
            macos_class_info[cls].append((method, param_count))

    print(f"[macos_csv] {len(macos_class_info)} classes loaded")

    rows: list[dict] = []

    with open_program(root) as program:
        fm = program.getFunctionManager()

        # Group Windows functions by class namespace
        class_functions: dict[str, list] = defaultdict(list)
        for fn in fm.getFunctions(True):
            ns = fn.getParentNamespace()
            if ns is None:
                continue
            ns_name = str(ns.getName())
            if ns_name not in macos_class_info:
                continue
            class_functions[ns_name].append(fn)

        ifc = create_configured_decompiler(program, timeout=20)
        try:
            for class_name, macos_ms in sorted(macos_class_info.items()):
                fns = class_functions.get(class_name, [])
                if not fns:
                    continue

                macos_names = {m for m, _ in macos_ms}
                macos_param_map: dict[str, int] = {m: p for m, p in macos_ms}

                named_names = {f.getName() for f in fns if not _is_generic_name(f.getName())}
                unnamed_fns = [f for f in fns if _is_generic_name(f.getName())]

                missing_methods = macos_names - named_names
                if not missing_methods:
                    continue
                if len(unnamed_fns) == 0:
                    continue
                if len(unnamed_fns) > len(missing_methods) * args.max_ambiguity_ratio:
                    continue

                missing_list = sorted(missing_methods)

                # For each unnamed function, find the best-scoring missing macOS method
                for un_fn in unnamed_fns:
                    fn_addr = int(str(un_fn.getEntryPoint()), 16)
                    fn_body = un_fn.getBody()
                    fn_size = fn_body.getNumAddresses() if fn_body is not None else 0

                    # Get param count from decompiler
                    win_params = 0
                    win_void = True
                    res = decompile_function(ifc, un_fn)
                    if res is not None:
                        high_fn = res.getHighFunction()
                        if high_fn is not None:
                            proto = high_fn.getFunctionPrototype()
                            if proto is not None:
                                win_params = proto.getNumParams()
                                rt = proto.getReturnType()
                                if rt is not None:
                                    win_void = str(rt.getName()).lower() in (
                                        "void",
                                        "undefined",
                                    )

                    # Score against each missing macOS method
                    best_score = -999.0
                    best_method = missing_list[0]
                    for m in missing_list:
                        mac_params = macos_param_map.get(m, 0)
                        score = 0.0
                        # Parameter count match (primary signal)
                        param_diff = abs(win_params - mac_params)
                        score -= param_diff * 3.0
                        if param_diff == 0:
                            score += 5.0
                        if score > best_score:
                            best_score = score
                            best_method = m

                    evidence = (
                        f"vocab_param_match_{win_params}of"
                        f"{len(missing_methods)}missing"
                    )
                    rows.append({
                        "address": f"0x{fn_addr:08x}",
                        "class_name": class_name,
                        "proposed_name": best_method,
                        "confidence": "low",
                        "evidence": evidence,
                    })

        finally:
            ifc.dispose()

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["address", "class_name", "proposed_name", "confidence", "evidence"],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
