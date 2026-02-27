#!/usr/bin/env python3
"""
Generate attach candidates for global __thiscall functions with typed first `this` pointer.

Selection:
  - function namespace is Global
  - calling convention is __thiscall
  - first parameter is pointer to a known class namespace type (non-void)

Output CSV columns:
  address,class_name,function_name,signature

Usage:
  .venv/bin/python new_scripts/generate_global_typed_this_attach_candidates.py \
    --out-csv tmp_decomp/global_typed_this_attach_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
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


def extract_first_param_class_name(func, class_names: set[str]) -> str:
    params = list(func.getParameters())
    if not params:
        return ""
    p0 = params[0]
    dt = p0.getDataType()
    base_name = ""
    if hasattr(dt, "getDataType"):
        try:
            base = dt.getDataType()
            if base is not None:
                base_name = base.getName() or ""
        except Exception:
            base_name = ""
    if not base_name:
        nm = dt.getName() or ""
        base_name = nm.replace("*", "").strip()
    if not base_name:
        return ""
    if base_name.lower() == "void":
        return ""
    if base_name not in class_names:
        return ""
    return base_name


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/global_typed_this_attach_candidates.csv",
        help="Output candidate CSV",
    )
    ap.add_argument("--allow-prefix", default="", help="Optional class-name prefix filter (e.g. T or C)")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        class_names: set[str] = set()
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            class_names.add(it_cls.next().getName())

        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            if f.getCallingConventionName() != "__thiscall":
                continue
            if not is_global_ns(f.getParentNamespace(), global_ns):
                continue
            cls = extract_first_param_class_name(f, class_names)
            if not cls:
                continue
            if args.allow_prefix and not cls.startswith(args.allow_prefix):
                continue
            ep = int(str(f.getEntryPoint()), 16) & 0xFFFFFFFF
            rows.append(
                {
                    "address": f"0x{ep:08x}",
                    "class_name": cls,
                    "function_name": f.getName(),
                    "signature": str(f.getSignature()),
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["address", "class_name", "function_name", "signature"],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:200]:
        print(f"{r['address']} {r['function_name']} -> {r['class_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
