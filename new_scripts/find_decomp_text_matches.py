#!/usr/bin/env python3
"""
Search decompiled C text for regex/text patterns and emit matching functions.

Usage:
  .venv/bin/python new_scripts/find_decomp_text_matches.py \
    --pattern "field_8e" --out-csv tmp_decomp/field8e_hits.csv

  .venv/bin/python new_scripts/find_decomp_text_matches.py \
    --pattern "selectedMetric88" --namespace TRailCluster --max-lines 4
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


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 45, None)
    if not res.decompileCompleted():
        return ""
    return str(res.getDecompiledFunction().getC())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", required=True, help="Regex pattern or literal text")
    ap.add_argument(
        "--literal",
        action="store_true",
        help="Treat --pattern as literal text instead of regex",
    )
    ap.add_argument("--namespace", default="", help="Optional namespace exact filter")
    ap.add_argument("--name-contains", default="", help="Optional function-name substring filter")
    ap.add_argument("--start", default="", help="Optional start address (hex/dec)")
    ap.add_argument("--end", default="", help="Optional end address exclusive (hex/dec)")
    ap.add_argument("--max-lines", type=int, default=3, help="Max matching lines per function")
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
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

    name_contains = args.name_contains.lower().strip()
    ns_filter = args.namespace.strip()
    start = parse_int(args.start) if args.start else None
    end = parse_int(args.end) if args.end else None

    if args.literal:
        pat = re.compile(re.escape(args.pattern))
    else:
        pat = re.compile(args.pattern)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()
        ifc = DecompInterface()
        ifc.openProgram(program)

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ep = int(str(f.getEntryPoint()), 16)
            if start is not None and ep < start:
                continue
            if end is not None and ep >= end:
                continue

            name = f.getName()
            if name_contains and name_contains not in name.lower():
                continue

            ns = f.getParentNamespace()
            ns_name = "Global" if ns is None else ns.getName()
            if ns == global_ns:
                ns_name = "Global"
            if ns_filter and ns_name != ns_filter:
                continue

            c = decompile_text(ifc, f)
            if not c:
                continue
            lines = [ln.rstrip() for ln in c.splitlines()]
            hits = [ln.strip() for ln in lines if pat.search(ln)]
            if not hits:
                continue

            rows.append(
                {
                    "address": f"0x{ep:08x}",
                    "namespace": ns_name,
                    "name": name,
                    "signature": str(f.getSignature()),
                    "match_count": str(len(hits)),
                    "match_lines": " | ".join(hits[: max(1, args.max_lines)]),
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "namespace",
                "name",
                "signature",
                "match_count",
                "match_lines",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
