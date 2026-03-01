#!/usr/bin/env python3
"""
QC: Match OrphanVtableAssignStub functions to classes via their embedded vtable address.

Each OrphanVtableAssignStub_XXXXXXXX function assigns vtable address XXXXXXXX.
We look up which class's vtable lives at that address and propose a class assignment.

Output CSV: address, stub_name, vtable_addr, class_name, confidence
"""
from __future__ import annotations
import argparse, csv
from pathlib import Path
from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()
    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    with open_program(root) as program:
        fm = program.getFunctionManager()
        sym_table = program.getSymbolTable()
        af = program.getAddressFactory().getDefaultAddressSpace()
        global_ns = program.getGlobalNamespace()

        # Build map: vtable_address -> class_name from g_vtblXxx symbols
        vtbl_map = {}  # int -> class_name
        for sym in sym_table.getAllSymbols(True):
            sname = str(sym.getName())
            if sname.startswith("g_vtbl"):
                class_name = sname[6:]  # strip g_vtbl
                addr_int = int(str(sym.getAddress()), 16)
                vtbl_map[addr_int] = class_name

        print(f"[vtable map] {len(vtbl_map)} vtable symbols found")

        # Find all OrphanVtableAssignStub functions
        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            name = fn.getName()
            if "OrphanVtableAssignStub" not in name:
                continue
            ep = int(str(fn.getEntryPoint()), 16)
            ns = fn.getParentNamespace()
            ns_name = "Global" if ns is None or ns == global_ns else ns.getName()

            # Extract embedded vtable address from name: OrphanVtableAssignStub_00XXXXXX
            import re
            m = re.search(r"OrphanVtableAssignStub_([0-9a-fA-F]{8})", name)
            if not m:
                continue
            vtbl_addr = int(m.group(1), 16)

            class_name = vtbl_map.get(vtbl_addr)
            rows.append({
                "address": f"0x{ep:08x}",
                "stub_name": name,
                "namespace": ns_name,
                "vtable_addr": f"0x{vtbl_addr:08x}",
                "class_name": class_name or "",
                "confidence": "high" if class_name else "unresolved",
            })

    matched = sum(1 for r in rows if r["class_name"])
    print(f"[stubs] total={len(rows)} matched={matched} unresolved={len(rows)-matched}")

    rows.sort(key=lambda r: int(r["address"], 16))
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["address","stub_name","namespace","vtable_addr","class_name","confidence"])
        w.writeheader()
        w.writerows(rows)
    print(f"[saved] {out_csv} rows={len(rows)}")

    for r in rows:
        if r["class_name"]:
            print(f"  {r['address']} {r['namespace']}::{r['stub_name']} => {r['class_name']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
