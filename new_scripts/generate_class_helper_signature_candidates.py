#!/usr/bin/env python3
"""
Generate conservative class-helper signature candidates.

Patterns:
  - Get*ClassNamePointer                 -> void* __cdecl ()
  - Create*Instance|*ControlPanel        -> <Namespace>* __cdecl ()
  - Construct*BaseState|*ControlPanel    -> <Namespace>* __thiscall (<Namespace>* this)
  - Destruct*MaybeFree|Destroy*ControlPanel
                                         -> <Namespace>* __thiscall (<Namespace>* this, byte freeSelfFlag)

Only class namespaces starting with 'T' are considered for class-pointer returns.

Usage:
  .venv/bin/python new_scripts/generate_class_helper_signature_candidates.py \
    --start 0x00583b00 --end 0x0058c200 \
    --out-csv tmp_decomp/trade_helper_sig_candidates.csv
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

RX_GETTER = re.compile(r"^Get[A-Za-z0-9_]*ClassNamePointer$")
RX_CREATE = re.compile(r"^Create[A-Za-z0-9_]*(Instance|ControlPanel|ControlPanelBasic)$")
RX_CONSTRUCT = re.compile(r"^Construct[A-Za-z0-9_]*(BaseState|ControlPanel|ControlPanelBasic)$")
RX_DESTRUCT = re.compile(r"^(Destruct[A-Za-z0-9_]*MaybeFree|Destroy[A-Za-z0-9_]*ControlPanel)$")
RX_NAME_CLASS_TOKEN = [
    re.compile(r"^Get(T[A-Za-z0-9_]+)ClassNamePointer$"),
    re.compile(r"^Create(T[A-Za-z0-9_]+)Instance$"),
    re.compile(r"^Construct(T[A-Za-z0-9_]+)BaseState$"),
    re.compile(r"^Destruct(T[A-Za-z0-9_]+?)(?:And)?MaybeFree$"),
]


def extract_class_token_from_name(name: str) -> str:
    for rx in RX_NAME_CLASS_TOKEN:
        m = rx.match(name)
        if m:
            return m.group(1)
    return ""


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="", help="Optional start address (inclusive)")
    ap.add_argument("--end", default="", help="Optional end address (exclusive)")
    ap.add_argument("--namespace-regex", default="", help="Optional namespace filter regex")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_int(args.start) if args.start else None
    end = parse_int(args.end) if args.end else None
    ns_re = re.compile(args.namespace_regex) if args.namespace_regex else None

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = Path(args.project_root).resolve() / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            addr = int(str(f.getEntryPoint()), 16)
            if start is not None and addr < start:
                continue
            if end is not None and addr >= end:
                continue

            ns = f.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()
            if ns_re and not ns_re.search(ns_name):
                continue

            name = f.getName()
            token = extract_class_token_from_name(name)
            if token and ns_name and token != ns_name:
                # Legacy mis-attachments can leave a function under the wrong namespace.
                # Skip those rows in auto-generated signature batches.
                continue

            cc = ""
            ret = ""
            params = ""
            reason = ""

            if RX_GETTER.match(name):
                cc = "__cdecl"
                ret = "void*"
                params = ""
                reason = "class_name_getter"
            elif ns_name.startswith("T") and RX_CREATE.match(name):
                cc = "__cdecl"
                ret = f"{ns_name}*"
                params = ""
                reason = "class_factory_create"
            elif ns_name.startswith("T") and RX_CONSTRUCT.match(name):
                cc = "__thiscall"
                ret = f"{ns_name}*"
                params = f"this:{ns_name}*"
                reason = "class_ctor_construct"
            elif ns_name.startswith("T") and RX_DESTRUCT.match(name):
                cc = "__thiscall"
                ret = f"{ns_name}*"
                params = f"this:{ns_name}*;freeSelfFlag:byte"
                reason = "class_dtor_destruct"
            else:
                continue

            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "calling_convention": cc,
                    "return_type": ret,
                    "params": params,
                    "reason": reason,
                    "namespace": ns_name,
                    "name": name,
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "calling_convention",
                "return_type",
                "params",
                "reason",
                "namespace",
                "name",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:220]:
        print(
            f"{r['address']} {r['namespace']}::{r['name']} -> "
            f"{r['calling_convention']} {r['return_type']} ({r['params']}) [{r['reason']}]"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
