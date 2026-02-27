#!/usr/bin/env python3
"""
Inventory methods whose first parameter ("this") uses a root-category stub type.

A row is reported when:
  - function is in a class namespace (non-Global)
  - function has at least one parameter
  - first parameter resolves to a base type in category "/"
  - base type length <= --max-stub-size (default 1)
  - a same-named datatype exists in /imperialism/classes

Usage:
  .venv/bin/python new_scripts/inventory_root_stub_this_types.py \
    --out-csv tmp_decomp/root_stub_this_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
import re
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--max-stub-size", type=int, default=1)
    ap.add_argument(
        "--class-regex",
        default="",
        help="Optional regex applied to class namespace names",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    class_re = re.compile(args.class_regex) if args.class_regex else None

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            if ns is None or ns == global_ns:
                continue
            ns_name = ns.getName()
            if class_re is not None and not class_re.search(ns_name):
                continue

            params = list(f.getParameters())
            if not params:
                continue
            p0 = params[0]
            p0_dt = p0.getDataType()
            p0_name = p0_dt.getName()

            try:
                base = p0_dt.getDataType() if p0_name.endswith("*") else p0_dt
                base_name = base.getName()
                base_cat = str(base.getCategoryPath().getPath())
                base_len = int(base.getLength())
            except Exception:
                continue

            if base_cat != "/":
                continue
            if base_len > args.max_stub_size:
                continue

            cls_dt = dtm.getDataType(CategoryPath("/imperialism/classes"), base_name)
            if cls_dt is None:
                continue

            rows.append(
                {
                    "address": f"0x{f.getEntryPoint().getOffset() & 0xFFFFFFFF:08x}",
                    "namespace": ns_name,
                    "function_name": f.getName(),
                    "signature": str(f.getSignature()),
                    "p0_type": p0_name,
                    "root_type_name": base_name,
                    "root_type_len": str(base_len),
                    "class_type_path": str(cls_dt.getCategoryPath().getPath()) + "/" + cls_dt.getName(),
                    "class_type_len": str(cls_dt.getLength()),
                }
            )

    rows.sort(key=lambda r: (r["namespace"], r["address"]))
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        fields = [
            "address",
            "namespace",
            "function_name",
            "signature",
            "p0_type",
            "root_type_name",
            "root_type_len",
            "class_type_path",
            "class_type_len",
        ]
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print(f"[done] out={out_csv} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
