#!/usr/bin/env python3
"""
Create canonical g_vtblT* labels from class-extract CSV rows.

Input CSV columns (expected):
  type_name,getter,desc,tname_addr,create,ctor,dtor,vtbl_addr

For each T* class:
1) if canonical g_vtblT* already exists -> skip
2) resolve vtbl address from vtbl_addr column, else infer from ctor decomp
3) create label g_vtbl<TClass> at resolved address

By default, shared vtable addresses are allowed (alias labels) but not made primary
when a primary symbol already exists at the same address.

Usage:
  .venv/bin/python new_scripts/extract_vtbl_labels_from_class_csv.py \
    --in-csv tmp_decomp/class_extract_from_all_getters_nearest.csv

  .venv/bin/python new_scripts/extract_vtbl_labels_from_class_csv.py \
    --in-csv tmp_decomp/class_extract_from_all_getters_nearest.csv --apply
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
VTBL_RE = re.compile(r"PTR_LAB_00([0-9a-fA-F]{6})")


def parse_hex(text: str | None) -> int | None:
    if text is None:
        return None
    t = text.strip()
    if not t:
        return None
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def infer_vtbl_from_ctor(ifc, ctor_func) -> int | None:
    if ctor_func is None:
        return None
    res = ifc.decompileFunction(ctor_func, 30, None)
    if not res.decompileCompleted():
        return None
    code = str(res.getDecompiledFunction().getC())
    hits = VTBL_RE.findall(code)
    if not hits:
        return None
    return int("00" + hits[-1], 16)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="Class extract CSV")
    ap.add_argument("--apply", action="store_true", help="Write labels")
    ap.add_argument(
        "--deny-shared-vtbl",
        action="store_true",
        help="Skip rows when target address already has a different canonical g_vtblT*",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("[done] no rows")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()

        ifc = DecompInterface()
        ifc.openProgram(program)

        existing_labels = set()
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            n = sit.next().getName()
            if n.startswith("g_vtblT"):
                existing_labels.add(n)

        candidates = []
        skip_non_t = skip_existing = skip_no_addr = 0
        for r in rows:
            tname = (r.get("type_name") or "").strip()
            if not tname.startswith("T"):
                skip_non_t += 1
                continue
            label = f"g_vtbl{tname}"
            if label in existing_labels:
                skip_existing += 1
                continue

            vtbl = parse_hex(r.get("vtbl_addr"))
            if vtbl is None:
                ctor = parse_hex(r.get("ctor"))
                if ctor is not None:
                    ctor_func = fm.getFunctionAt(af.getAddress(f"0x{ctor:08x}"))
                    vtbl = infer_vtbl_from_ctor(ifc, ctor_func)
            if vtbl is None:
                skip_no_addr += 1
                continue

            candidates.append(
                {
                    "tname": tname,
                    "label": label,
                    "vtbl_addr": f"0x{vtbl:08x}",
                }
            )

        print(
            f"[candidates] {len(candidates)} "
            f"skip_non_t={skip_non_t} skip_existing={skip_existing} skip_no_addr={skip_no_addr}"
        )
        for c in candidates[:240]:
            print(f"{c['tname']},{c['vtbl_addr']},{c['label']}")
        if len(candidates) > 240:
            print(f"... ({len(candidates) - 240} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write labels")
            return 0

        tx = program.startTransaction("Extract vtbl labels from class csv")
        ok = skip = fail = 0
        try:
            for c in candidates:
                addr = af.getAddress(c["vtbl_addr"])
                label = c["label"]
                syms = list(st.getSymbols(addr))
                if any(s.getName() == label for s in syms):
                    skip += 1
                    continue
                conflict = any(
                    s.getName().startswith("g_vtblT") and s.getName() != label for s in syms
                )
                if conflict and args.deny_shared_vtbl:
                    skip += 1
                    continue
                try:
                    sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    if not syms:
                        sym.setPrimary()
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {c['vtbl_addr']} {label} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("extract vtbl labels from class csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
