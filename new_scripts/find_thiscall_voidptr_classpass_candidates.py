#!/usr/bin/env python3
"""
Find likely class methods currently typed as __thiscall with void* first parameter.

Heuristic:
- target function calling convention is "__thiscall"
- target first formal parameter is void* (or equivalent pointer-to-void type)
- inspect direct CALL xrefs and count caller class namespaces
- rank by dominant caller-class ownership ratio

This helps locate functions that should likely be attached/retyped as class methods.

Usage:
  .venv/bin/python new_scripts/find_thiscall_voidptr_classpass_candidates.py
  .venv/bin/python new_scripts/find_thiscall_voidptr_classpass_candidates.py --min-class-calls 2 --min-ratio 0.75
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def is_global_ns(ns, global_ns) -> bool:
    return ns is None or ns == global_ns or ns.getName() == "Global"


def is_void_pointer(dt) -> bool:
    # Robust across formatting variants: "void *", "void*", "pointer"->base "void".
    nm = (dt.getName() or "").replace(" ", "").lower()
    if nm in ("void*", "pointer"):
        if nm == "void*":
            return True
    if hasattr(dt, "getDataType"):
        try:
            base = dt.getDataType()
            if base is not None:
                bnm = (base.getName() or "").strip().lower()
                if bnm == "void":
                    return True
        except Exception:
            pass
    return nm == "void*"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-class-calls", type=int, default=1)
    ap.add_argument("--min-ratio", type=float, default=0.60)
    ap.add_argument("--max-print", type=int, default=120)
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/thiscall_voidptr_classpass_candidates.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = (root / args.out_csv).resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        class_names = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            class_names.add(it_cls.next().getName())

        fit = fm.getFunctions(True)
        scanned = 0
        while fit.hasNext():
            f = fit.next()
            scanned += 1
            if f.getCallingConventionName() != "__thiscall":
                continue
            params = list(f.getParameters())
            if len(params) < 1:
                continue
            p0 = params[0]
            if not is_void_pointer(p0.getDataType()):
                continue

            class_counts: dict[str, int] = defaultdict(int)
            total_calls = 0
            refs = rm.getReferencesTo(f.getEntryPoint())
            while refs.hasNext():
                ref = refs.next()
                from_addr = ref.getFromAddress()
                ins = listing.getInstructionAt(from_addr)
                if ins is None or str(ins.getMnemonicString()).upper() != "CALL":
                    continue
                caller = fm.getFunctionContaining(from_addr)
                if caller is None:
                    continue
                total_calls += 1
                ns = caller.getParentNamespace()
                if ns is None:
                    continue
                nsn = ns.getName()
                if nsn in class_names:
                    class_counts[nsn] += 1

            class_total = sum(class_counts.values())
            if class_total < args.min_class_calls:
                continue
            dom_cls, dom_cnt = max(class_counts.items(), key=lambda kv: kv[1])
            ratio = dom_cnt / float(class_total) if class_total else 0.0
            if ratio < args.min_ratio:
                continue

            ns = f.getParentNamespace()
            cur_ns_name = ns.getName() if ns is not None else "Global"
            rows.append(
                {
                    "address": f"0x{f.getEntryPoint().getOffset() & 0xFFFFFFFF:08x}",
                    "name": f.getName(),
                    "current_namespace": cur_ns_name,
                    "signature": str(f.getSignature()),
                    "dominant_class": dom_cls,
                    "dominant_calls": str(dom_cnt),
                    "class_calls_total": str(class_total),
                    "all_calls_total": str(total_calls),
                    "dominant_ratio": f"{ratio:.2f}",
                }
            )

    rows.sort(
        key=lambda r: (
            -float(r["dominant_ratio"]),
            -int(r["class_calls_total"]),
            int(r["address"], 16),
        )
    )

    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "name",
                "current_namespace",
                "signature",
                "dominant_class",
                "dominant_calls",
                "class_calls_total",
                "all_calls_total",
                "dominant_ratio",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[done] rows={len(rows)} out={out_csv} "
        f"min_class_calls={args.min_class_calls} min_ratio={args.min_ratio:.2f}"
    )
    for r in rows[: args.max_print]:
        print(
            f"{r['address']} {r['name']} ns={r['current_namespace']} "
            f"-> {r['dominant_class']} dom={r['dominant_calls']}/{r['class_calls_total']} "
            f"ratio={r['dominant_ratio']}"
        )
    if len(rows) > args.max_print:
        print(f"... ({len(rows) - args.max_print} more)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
