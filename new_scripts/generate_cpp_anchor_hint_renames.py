#!/usr/bin/env python3
"""
Generate hint renames for unresolved FUN_* functions using embedded .cpp string anchors.

Heuristic:
  - Find defined strings containing ".cpp"
  - For each string, collect code xrefs
  - Map xrefs to containing functions
  - For each FUN_* function, choose the most-referenced anchor basename
  - Emit CSV for apply_function_renames_csv.py

Output CSV columns:
  address,new_name,comment

Usage:
  .venv/bin/python new_scripts/generate_cpp_anchor_hint_renames.py \
    [out_csv] [project_root] [--min-hits 1] [--max-rows 0]
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
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


def sanitize_anchor_name(text: str) -> str:
    s = text.replace("\\", "/")
    s = s.rsplit("/", 1)[-1]
    if s.lower().endswith(".cpp"):
        s = s[:-4]
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "CppAnchor"
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "out_csv",
        nargs="?",
        default="tmp_decomp/cpp_anchor_fun_hint_renames.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "project_root",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument("--min-hits", type=int, default=1, help="Minimum xref hits per chosen anchor")
    ap.add_argument("--max-rows", type=int, default=0, help="0 = unlimited")
    args = ap.parse_args()

    out_csv = Path(args.out_csv)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    per_func_anchor_hits: dict[tuple[int, str], Counter[str]] = defaultdict(Counter)
    anchor_texts: dict[str, str] = {}

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()

        str_it = listing.getDefinedData(True)
        while str_it.hasNext():
            d = str_it.next()
            v = d.getValue()
            if v is None:
                continue
            txt = str(v)
            if ".cpp" not in txt.lower():
                continue

            refs = rm.getReferencesTo(d.getAddress())
            anchor_name = sanitize_anchor_name(txt)
            anchor_texts[anchor_name] = txt
            for ref in refs:
                from_addr = ref.getFromAddress()
                f = fm.getFunctionContaining(from_addr)
                if f is None:
                    continue
                fname = f.getName()
                if not fname.startswith("FUN_"):
                    continue
                ep_txt = str(f.getEntryPoint())
                if ep_txt.startswith("EXTERNAL:"):
                    continue
                try:
                    ep_int = int(ep_txt, 16)
                except Exception:
                    continue
                per_func_anchor_hits[(ep_int, fname)][anchor_name] += 1

    rows = []
    seen_names = set()
    for (ep_int, fname), counter in per_func_anchor_hits.items():
        anchor_name, hit_count = max(counter.items(), key=lambda kv: kv[1])
        if hit_count < args.min_hits:
            continue
        new_name = f"Cluster_{anchor_name}Hint_{ep_int:08x}"
        if new_name in seen_names:
            new_name = f"{new_name}_{hit_count}"
        seen_names.add(new_name)
        src_txt = anchor_texts.get(anchor_name, anchor_name)
        rows.append(
            {
                "address": f"0x{ep_int:08x}",
                "new_name": new_name,
                "comment": (
                    f"[CppAnchor] unresolved function referenced by source anchor "
                    f"'{src_txt}' (hits={hit_count})."
                ),
                "old_name": fname,
                "anchor_name": anchor_name,
                "hit_count": str(hit_count),
            }
        )

    rows.sort(key=lambda r: (-int(r["hit_count"]), r["address"]))
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["address", "new_name", "comment", "old_name", "anchor_name", "hit_count"],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"min_hits={args.min_hits} unique_functions={len(per_func_anchor_hits)}"
    )
    for r in rows[:120]:
        print(
            f"{r['address']},{r['old_name']},{r['new_name']},"
            f"anchor={r['anchor_name']},hits={r['hit_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
