#!/usr/bin/env python3
"""
Derive pointer->class ownership candidates from runtime-class pointer ref inventory.

Input:
  CSV from inventory_runtime_class_ptr_initializers.py (..._refs.csv)

Outputs:
  - <out-prefix>_ptr_summary.csv
  - <out-prefix>_strong_ptrs.csv
  - <out-prefix>_attach_candidates.csv

Usage:
  uv run impk derive_runtime_class_ptr_owner_candidates \
    --in-refs-csv tmp_decomp/batch761_runtime_class_ptr_inventory_refs.csv \
    --out-prefix tmp_decomp/batch761_runtime_class_ptr_owner
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
RX_CLASS_TOKEN = re.compile(r"T[A-Z][A-Za-z0-9_]*")
RX_GENERIC_FN = re.compile(r"^(FUN_|thunk_|WrapperFor_|Cluster_|InitializeRuntimeClassFields_)")

def pick_class_token(function_name: str, function_namespace: str, class_names: set[str]) -> str:
    name = function_name or ""
    ns = (function_namespace or "").strip()

    # Strongest signal: attached class namespace from Ghidra.
    if ns and ns in class_names:
        return ns

    # Prefer exact known class namespace substrings (most stable).
    contained = [cls for cls in class_names if cls.startswith("T") and cls in name]
    if contained:
        contained.sort(key=lambda c: (-len(c), c))
        return contained[0]

    # Fallback for not-yet-extracted namespaces.
    m = RX_CLASS_TOKEN.search(name)
    if not m:
        return ""
    token = m.group(0)
    # Trim obvious action suffixes when no exact namespace hit exists.
    for suffix in (
        "AndMaybeFree",
        "AndMaybeFreeImpl",
        "Impl",
        "Instance",
        "BaseState",
        "State",
    ):
        if token.endswith(suffix) and len(token) > len(suffix) + 1:
            token = token[: -len(suffix)]
            break
    return token

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--in-refs-csv",
        default="tmp_decomp/batch761_runtime_class_ptr_inventory_refs.csv",
        help="Input refs CSV",
    )
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/runtime_class_ptr_owner",
        help="Output prefix (without suffix)",
    )
    ap.add_argument("--min-hits", type=int, default=3)
    ap.add_argument("--min-ratio", type=float, default=0.70)
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    in_refs = Path(args.in_refs_csv)
    if not in_refs.is_absolute():
        in_refs = root / in_refs
    if not in_refs.exists():
        print(f"[error] missing refs csv: {in_refs}")
        return 1

    out_prefix = Path(args.out_prefix)
    if not out_prefix.is_absolute():
        out_prefix = root / out_prefix
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    out_summary = out_prefix.with_name(out_prefix.name + "_ptr_summary.csv")
    out_strong = out_prefix.with_name(out_prefix.name + "_strong_ptrs.csv")
    out_attach = out_prefix.with_name(out_prefix.name + "_attach_candidates.csv")

    rows = list(csv.DictReader(in_refs.open("r", encoding="utf-8", newline="")))

    # Build class namespace set for filtering.
    class_names: set[str] = set()
    with open_program(root) as program:
        st = program.getSymbolTable()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            class_names.add(it_cls.next().getName())

    ptr_token_counts: dict[str, Counter[str]] = defaultdict(Counter)
    ptr_total = Counter()
    ptr_rows: dict[str, list[dict[str, str]]] = defaultdict(list)

    for r in rows:
        if (r.get("initializer_like") or "0") != "1":
            continue
        ptr = (r.get("ptr_symbol") or "").strip()
        fn_name = (r.get("function_name") or "").strip()
        if not ptr or not fn_name or fn_name == "<no_func>":
            continue

        token = pick_class_token(
            fn_name,
            (r.get("function_namespace") or "").strip(),
            class_names,
        )
        ptr_total[ptr] += 1
        ptr_rows[ptr].append(r)
        if token:
            ptr_token_counts[ptr][token] += 1

    summary_rows: list[dict[str, str]] = []
    strong_rows: list[dict[str, str]] = []
    strong_ptr_to_class: dict[str, str] = {}

    for ptr in sorted(ptr_total.keys()):
        total = int(ptr_total[ptr])
        counts = ptr_token_counts.get(ptr, Counter())
        if counts:
            top_class, top_hits = counts.most_common(1)[0]
            ratio = (top_hits / float(total)) if total else 0.0
        else:
            top_class, top_hits, ratio = "", 0, 0.0

        token_blob = ";".join(f"{k}:{v}" for k, v in counts.most_common(12))
        row = {
            "ptr_symbol": ptr,
            "initializer_rows": str(total),
            "class_token_rows": str(sum(counts.values())),
            "top_class": top_class,
            "top_hits": str(top_hits),
            "top_ratio": f"{ratio:.2f}",
            "top_class_exists_as_namespace": "1" if top_class in class_names else "0",
            "class_token_counts": token_blob,
        }
        summary_rows.append(row)

        if (
            top_class
            and top_hits >= args.min_hits
            and ratio >= args.min_ratio
            and top_class in class_names
        ):
            strong_rows.append(row)
            strong_ptr_to_class[ptr] = top_class

    # Conservative attach candidates:
    # - global function
    # - initializer-like
    # - pointer has strong owner class
    # - function name still generic wrapper/cluster/fun
    # - skip rows already carrying explicit class token in name
    attach_rows: list[dict[str, str]] = []
    seen_attach = set()
    for ptr, owner_cls in strong_ptr_to_class.items():
        for r in ptr_rows.get(ptr, []):
            fn_addr = (r.get("function_addr") or "").strip()
            fn_name = (r.get("function_name") or "").strip()
            fn_ns = (r.get("function_namespace") or "").strip()
            fn_global = (r.get("function_is_global") or "1").strip()
            if not fn_addr or fn_name in ("", "<no_func>"):
                continue
            if fn_global != "1":
                continue
            if fn_ns:
                continue
            if not RX_GENERIC_FN.match(fn_name):
                continue
            if pick_class_token(fn_name, fn_ns, class_names):
                continue
            key = (fn_addr, owner_cls)
            if key in seen_attach:
                continue
            seen_attach.add(key)
            attach_rows.append(
                {
                    "address": fn_addr,
                    "class_name": owner_cls,
                    "ptr_symbol": ptr,
                    "function_name": fn_name,
                    "reason": "strong runtime ptr owner class",
                }
            )

    summary_rows.sort(key=lambda r: (r["ptr_symbol"]))
    strong_rows.sort(key=lambda r: (r["ptr_symbol"]))
    attach_rows.sort(key=lambda r: int(r["address"], 16))

    with out_summary.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "ptr_symbol",
                "initializer_rows",
                "class_token_rows",
                "top_class",
                "top_hits",
                "top_ratio",
                "top_class_exists_as_namespace",
                "class_token_counts",
            ],
        )
        w.writeheader()
        w.writerows(summary_rows)

    with out_strong.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "ptr_symbol",
                "initializer_rows",
                "class_token_rows",
                "top_class",
                "top_hits",
                "top_ratio",
                "top_class_exists_as_namespace",
                "class_token_counts",
            ],
        )
        w.writeheader()
        w.writerows(strong_rows)

    with out_attach.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["address", "class_name", "ptr_symbol", "function_name", "reason"],
        )
        w.writeheader()
        w.writerows(attach_rows)

    print(f"[saved] {out_summary} rows={len(summary_rows)}")
    print(f"[saved] {out_strong} rows={len(strong_rows)}")
    print(f"[saved] {out_attach} rows={len(attach_rows)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
