#!/usr/bin/env python3
"""
Generate rename CSV by extracting demangled leaf names from MSVC mangled symbols.

Heuristic:
  ?Name@Class@@...  -> Name

Outputs CSV compatible with apply_function_renames_csv.py:
  address,new_name,comment

Usage:
  .venv/bin/python new_scripts/generate_mangled_leaf_renames.py \
    --start 0x00583b00 --end 0x0058c200 \
    --name-prefixes Create Construct Destruct WrapperFor \
    --out-csv tmp_decomp/trade_mangled_leaf_renames.csv
"""

from __future__ import annotations

import argparse
import csv
import re
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


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def sanitize_identifier(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", name)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return ""
    if s[0].isdigit():
        s = "_" + s
    return s


def demangled_leaf(name: str) -> str:
    if not name.startswith("?"):
        return ""
    body = name[1:]
    i = body.find("@@")
    if i <= 0:
        return ""
    core = body[:i]
    leaf = core.split("@")[0].strip()
    if not leaf:
        return ""
    if leaf.startswith("?"):
        # skip special operators/ctors that need custom handling
        return ""
    return sanitize_identifier(leaf)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="", help="Optional address start (inclusive)")
    ap.add_argument("--end", default="", help="Optional address end (exclusive)")
    ap.add_argument(
        "--name-prefixes",
        nargs="*",
        default=[],
        help="Optional allowed demangled leaf prefixes (e.g. Create Construct Destruct)",
    )
    ap.add_argument("--namespace-regex", default="", help="Optional namespace name regex")
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_int(args.start) if args.start else None
    end = parse_int(args.end) if args.end else None
    prefixes = tuple(args.name_prefixes)
    ns_re = re.compile(args.namespace_regex) if args.namespace_regex else None

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = Path(args.project_root).resolve() / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    name_buckets: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)

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
            old = f.getName()
            leaf = demangled_leaf(old)
            if not leaf:
                continue
            if prefixes and not any(leaf.startswith(p) for p in prefixes):
                continue
            ns = f.getParentNamespace()
            ns_name = "" if ns is None else ns.getName()
            if ns_re and not ns_re.search(ns_name):
                continue
            name_buckets[(ns_name, leaf)].append((addr, old))

    for (ns_name, leaf), items in sorted(name_buckets.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        # Stable: prefer higher address as canonical unsuffixed name, suffix others.
        items_sorted = sorted(items, key=lambda t: t[0], reverse=True)
        for idx, (addr, old) in enumerate(items_sorted):
            new_name = leaf if idx == 0 else f"{leaf}_At{addr:08x}"
            if old == new_name:
                continue
            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "new_name": new_name,
                    "comment": "demangled leaf extracted from mangled MSVC symbol",
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"start={args.start or '<none>'} end={args.end or '<none>'}"
    )
    for r in rows[:200]:
        print(f"{r['address']} -> {r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
