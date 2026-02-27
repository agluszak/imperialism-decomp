#!/usr/bin/env python3
"""
Build class-model inventory and gap reports from the current imperialism-decomp project.

Outputs:
  - class_model_inventory.csv
  - class_model_gaps.csv
  - class_model_inventory_summary.txt

Usage:
  .venv/bin/python new_scripts/build_class_model_inventory.py [--out-dir tmp_decomp]
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
RX_DEFAULT = re.compile(r"^(FUN_|thunk_FUN_)")
RX_VTBL_CANONICAL = re.compile(r"^g_vtbl(T[A-Za-z0-9_]+)$")
RX_VTBL_CANONICAL_UNDERSCORE = re.compile(r"^g_vtbl_(T[A-Za-z0-9_]+)$")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def detect_descriptor_mode(program, desc_sym) -> tuple[str, str]:
    """Return (mode, detail) for g_pClassDescT* target shape."""
    listing = program.getListing()
    data = listing.getDataAt(desc_sym.getAddress())
    if data is None:
        return ("missing_data", "")
    try:
        ptr = data.getValue()
    except Exception:
        return ("unreadable_data", data.getDataType().getName())
    if ptr is None:
        return ("null_pointer", data.getDataType().getName())

    # Pointer data can resolve as Address or Scalar depending on local typing.
    taddr = None
    if hasattr(ptr, "getOffset"):
        taddr = ptr
    elif hasattr(ptr, "getUnsignedValue"):
        try:
            af = program.getAddressFactory().getDefaultAddressSpace()
            taddr = af.getAddress(f"0x{int(ptr.getUnsignedValue()):08x}")
        except Exception:
            taddr = None
    if taddr is None:
        return ("unreadable_pointer_value", str(ptr))

    target = listing.getDataAt(taddr)
    if target is None:
        return ("target_missing_data", data.getDataType().getName())
    tname = target.getDataType().getName()
    sval = str(target.getValue()) if target.getValue() is not None else ""
    if tname.lower().startswith("string") and sval:
        return ("points_to_typename_string", sval)
    if "undefined" in tname.lower():
        return ("points_to_undefined_data", tname)
    return ("points_to_typed_data", tname)


def extract_vtbl_class_name(sym_name: str) -> str | None:
    m = RX_VTBL_CANONICAL.match(sym_name)
    if m:
        cls = m.group(1)
    else:
        m = RX_VTBL_CANONICAL_UNDERSCORE.match(sym_name)
        if not m:
            return None
        cls = m.group(1)

    # Exclude non-canonical helper/slot labels that leak into inventory.
    if "_Slot" in cls or "Candidate_" in cls or "Family_" in cls:
        return None
    return cls


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-dir",
        default="tmp_decomp",
        help="Output directory for inventory/gap reports",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_dir = (root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    out_inventory = out_dir / "class_model_inventory.csv"
    out_gaps = out_dir / "class_model_gaps.csv"
    out_summary = out_dir / "class_model_inventory_summary.txt"

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        all_syms = []
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            all_syms.append(sit.next())

        desc_syms = {s.getName().replace("g_pClassDesc", ""): s for s in all_syms if s.getName().startswith("g_pClassDescT")}
        vtbl_syms = {}
        for s in all_syms:
            cls = extract_vtbl_class_name(s.getName())
            if cls is None:
                continue
            if cls not in vtbl_syms:
                vtbl_syms[cls] = s
        type_syms = {s.getName().replace("g_szTypeName", ""): s for s in all_syms if s.getName().startswith("g_szTypeNameT")}

        # Struct datatypes keyed by exact T* name.
        struct_names = set()
        dt_it = dtm.getAllDataTypes()
        while dt_it.hasNext():
            dt = dt_it.next()
            n = dt.getName()
            if not n.startswith("T"):
                continue
            cls = dt.getClass().getSimpleName()
            if "Structure" in cls:
                struct_names.add(n)

        # Per-namespace method counts/default-name counts.
        ns_total: dict[str, int] = {}
        ns_default: dict[str, int] = {}
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            ns = f.getParentNamespace()
            if ns is None or ns == global_ns or ns.getName() == "Global":
                continue
            name = ns.getName()
            ns_total[name] = ns_total.get(name, 0) + 1
            if RX_DEFAULT.match(f.getName()):
                ns_default[name] = ns_default.get(name, 0) + 1

        classes = sorted(set(desc_syms) | set(vtbl_syms) | set(type_syms) | set(struct_names) | set(ns_total))

        inventory_rows = []
        gap_rows = []
        for cls in classes:
            desc = desc_syms.get(cls)
            vtbl = vtbl_syms.get(cls)
            tname = type_syms.get(cls)
            has_struct = cls in struct_names
            method_total = ns_total.get(cls, 0)
            method_default = ns_default.get(cls, 0)

            desc_mode = ""
            desc_detail = ""
            if desc is not None:
                desc_mode, desc_detail = detect_descriptor_mode(program, desc)

            row = {
                "class_name": cls,
                "has_class_desc_symbol": "1" if desc is not None else "0",
                "class_desc_addr": str(desc.getAddress()) if desc is not None else "",
                "class_desc_mode": desc_mode,
                "class_desc_detail": desc_detail,
                "has_vtbl_symbol": "1" if vtbl is not None else "0",
                "vtbl_addr": str(vtbl.getAddress()) if vtbl is not None else "",
                "has_typename_symbol": "1" if tname is not None else "0",
                "typename_addr": str(tname.getAddress()) if tname is not None else "",
                "has_struct_type": "1" if has_struct else "0",
                "method_count_in_namespace": str(method_total),
                "default_named_methods_in_namespace": str(method_default),
            }
            inventory_rows.append(row)

            if not has_struct:
                gap_rows.append({"class_name": cls, "gap_type": "missing_struct_type", "detail": ""})
            if desc is None:
                gap_rows.append({"class_name": cls, "gap_type": "missing_class_desc_symbol", "detail": ""})
            if vtbl is None:
                gap_rows.append({"class_name": cls, "gap_type": "missing_vtbl_symbol", "detail": ""})
            if method_default > 0:
                gap_rows.append(
                    {
                        "class_name": cls,
                        "gap_type": "has_default_named_methods",
                        "detail": f"default={method_default}/total={method_total}",
                    }
                )
            if desc_mode == "points_to_typename_string":
                gap_rows.append(
                    {
                        "class_name": cls,
                        "gap_type": "descriptor_points_to_string",
                        "detail": desc_detail,
                    }
                )

        with out_inventory.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "class_name",
                    "has_class_desc_symbol",
                    "class_desc_addr",
                    "class_desc_mode",
                    "class_desc_detail",
                    "has_vtbl_symbol",
                    "vtbl_addr",
                    "has_typename_symbol",
                    "typename_addr",
                    "has_struct_type",
                    "method_count_in_namespace",
                    "default_named_methods_in_namespace",
                ],
            )
            w.writeheader()
            w.writerows(inventory_rows)

        with out_gaps.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["class_name", "gap_type", "detail"])
            w.writeheader()
            w.writerows(gap_rows)

        summary_lines = [
            f"classes_total={len(classes)}",
            f"class_desc_count={len(desc_syms)}",
            f"vtbl_count={len(vtbl_syms)}",
            f"typename_count={len(type_syms)}",
            f"struct_type_count={len(struct_names)}",
            f"classes_missing_struct={sum(1 for r in inventory_rows if r['has_struct_type'] == '0')}",
            f"classes_missing_vtbl={sum(1 for r in inventory_rows if r['has_vtbl_symbol'] == '0')}",
            f"classes_missing_class_desc={sum(1 for r in inventory_rows if r['has_class_desc_symbol'] == '0')}",
            f"classes_with_default_methods={sum(1 for r in inventory_rows if int(r['default_named_methods_in_namespace']) > 0)}",
            f"class_desc_pointing_to_string={sum(1 for r in inventory_rows if r['class_desc_mode'] == 'points_to_typename_string')}",
        ]
        out_summary.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(f"[done] inventory={out_inventory}")
    print(f"[done] gaps={out_gaps}")
    print(f"[done] summary={out_summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
