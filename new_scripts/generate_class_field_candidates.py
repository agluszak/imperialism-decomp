#!/usr/bin/env python3
"""
Generate class field-offset candidates by mining decompiled code of methods
in one or more class namespaces.

Heuristic:
  - Scan decompiled C text for `(this + 0xNN)` patterns.
  - Aggregate offsets/frequency per class.
  - Emit candidate CSV with example methods.

Usage:
  .venv/bin/python new_scripts/generate_class_field_candidates.py \
    --classes TViewMgr TGameWindow TMultiplayerMgr TEditText TAmtBarCluster \
    --out tmp_decomp/class_field_candidates_batch356_top5.csv
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

# NOTE:
# We intentionally exclude patterns where base is dereferenced (e.g. `*this + 0x94`),
# which usually represent vtable slot calls, not instance fields.
RX_BASE_OFFSET_FMT = r"(?<!\*)(?:\(int\)\s*)?\b{base}\b\s*\+\s*0x([0-9a-fA-F]+)"
RX_BASE_INDEX_HEX_FMT = r"(?<!\*)\b{base}\b\s*\[\s*0x([0-9a-fA-F]+)\s*\]"
RX_BASE_INDEX_DEC_FMT = r"(?<!\*)\b{base}\b\s*\[\s*([0-9]+)\s*\]"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 30, None)
    if not res.decompileCompleted():
        return ""
    return str(res.getDecompiledFunction().getC())


def is_probable_vtable_expr(code: str, match_start: int) -> bool:
    """
    Filter false positives like `*(int *)this + 0x1a8` (vtable slot offsets),
    which are not instance field accesses.
    """
    prefix = code[max(0, match_start - 32) : match_start]
    return re.search(r"\*\s*\([^)]*\)\s*$", prefix) is not None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", nargs="+", required=True, help="Class namespace names")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    wanted = set(args.classes)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        global_ns = program.getGlobalNamespace()
        ifc = DecompInterface()
        ifc.openProgram(program)

        # class -> offset -> set(method names)
        offset_methods: dict[str, dict[int, set[str]]] = defaultdict(lambda: defaultdict(set))
        class_method_count: dict[str, int] = defaultdict(int)

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            if ns is None or ns == global_ns or ns.getName() == "Global":
                continue
            cname = ns.getName()
            if cname not in wanted:
                continue
            class_method_count[cname] += 1
            c_code = decompile_text(ifc, f)
            if not c_code:
                continue
            base_names = [
                "this",
                "param_1",
                "pThis",
                "in_ECX",
                "this_00",
                "this_01",
                "this_02",
            ]
            for base in base_names:
                rx_off = re.compile(RX_BASE_OFFSET_FMT.format(base=re.escape(base)))
                for m in rx_off.finditer(c_code):
                    if is_probable_vtable_expr(c_code, m.start()):
                        continue
                    off = int(m.group(1), 16)
                    offset_methods[cname][off].add(f"{f.getName()}#byte")

                rx_idx_h = re.compile(RX_BASE_INDEX_HEX_FMT.format(base=re.escape(base)))
                for m in rx_idx_h.finditer(c_code):
                    idx = int(m.group(1), 16)
                    off = idx * 4
                    offset_methods[cname][off].add(f"{f.getName()}#idx4")

                rx_idx_d = re.compile(RX_BASE_INDEX_DEC_FMT.format(base=re.escape(base)))
                for m in rx_idx_d.finditer(c_code):
                    idx = int(m.group(1), 10)
                    off = idx * 4
                    offset_methods[cname][off].add(f"{f.getName()}#idx4")

    rows = []
    for cname in sorted(wanted):
        for off in sorted(offset_methods[cname]):
            methods = sorted(offset_methods[cname][off])
            byte_hits = [m for m in methods if m.endswith("#byte")]
            idx4_hits = [m for m in methods if m.endswith("#idx4")]
            if byte_hits and idx4_hits:
                mode = "mixed"
            elif idx4_hits:
                mode = "idx4_only"
            else:
                mode = "byte_only"
            rows.append(
                {
                    "class_name": cname,
                    "offset_hex": f"0x{off:x}",
                    "offset_dec": str(off),
                    "hit_count": str(len(methods)),
                    "method_count_in_class": str(class_method_count.get(cname, 0)),
                    "offset_mode": mode,
                    "sample_methods": ";".join(m.rsplit("#", 1)[0] for m in methods[:8]),
                }
            )

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "class_name",
                "offset_hex",
                "offset_dec",
                "hit_count",
                "method_count_in_class",
                "offset_mode",
                "sample_methods",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[done] out={out_csv}")
    print(f"[done] rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
