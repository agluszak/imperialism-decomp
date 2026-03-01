#!/usr/bin/env python3
"""
QC: Vtable slot coverage - for each class with a g_vtbl symbol, count how many
virtual slots point to named vs generic functions.

Output CSV: class_name, vtable_addr, total_slots, named_slots, generic_slots, coverage_pct
"""
from __future__ import annotations
import argparse, csv
from pathlib import Path
from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--min-slots", type=int, default=4, help="Min slots to include")
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
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()
        global_ns = program.getGlobalNamespace()

        # Find all g_vtbl* symbols
        vtbl_syms = []
        for sym in sym_table.getAllSymbols(True):
            sname = str(sym.getName())
            if sname.startswith("g_vtbl"):
                class_name = sname[6:]
                vtbl_syms.append((class_name, sym.getAddress()))

        print(f"[vtable syms] {len(vtbl_syms)}")

        for class_name, vtbl_addr in vtbl_syms:
            vtbl_int = int(str(vtbl_addr), 16)
            total = 0
            named = 0
            generic = 0
            generic_names = []

            # Walk dwords until we hit a non-code-pointer
            offset = 0
            while True:
                slot_addr = af.getAddress(f"{vtbl_int + offset:08x}")
                try:
                    dword_bytes = bytearray(4)
                    count = mem.getBytes(slot_addr, dword_bytes)
                    if count < 4:
                        break
                    # Little-endian dword
                    ptr = int.from_bytes(dword_bytes, 'little')
                except Exception:
                    break

                # Check if this pointer is a valid function
                ptr_addr = af.getAddress(f"{ptr:08x}")
                fn = fm.getFunctionAt(ptr_addr)
                if fn is None:
                    break

                total += 1
                fn_name = fn.getName()
                is_generic = (
                    fn_name.startswith("FUN_") or
                    fn_name.startswith("thunk_FUN_") or
                    fn_name.startswith("Cluster_") or
                    (fn_name.startswith("thunk_") and fn_name[6:].startswith("FUN_"))
                )
                if is_generic:
                    generic += 1
                    generic_names.append(f"slot{total-1}:{fn_name}")
                else:
                    named += 1
                offset += 4

                # Safety cap
                if total > 200:
                    break

            if total < args.min_slots:
                continue

            pct = named / total * 100 if total > 0 else 0
            rows.append({
                "class_name": class_name,
                "vtable_addr": f"0x{vtbl_int:08x}",
                "total_slots": total,
                "named_slots": named,
                "generic_slots": generic,
                "coverage_pct": f"{pct:.0f}",
                "generic_slot_names": "; ".join(generic_names[:5]),
            })

    rows.sort(key=lambda r: int(r["generic_slots"]), reverse=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["class_name","vtable_addr","total_slots","named_slots","generic_slots","coverage_pct","generic_slot_names"])
        w.writeheader()
        w.writerows(rows)
    print(f"[saved] {out_csv} rows={len(rows)}")

    total_classes = len(rows)
    full_coverage = sum(1 for r in rows if int(r["generic_slots"]) == 0)
    print(f"[coverage] {full_coverage}/{total_classes} classes at 100% vtable slot coverage")
    print(f"\n{'Class':<40} {'slots':>6} {'named':>6} {'generic':>8} {'pct':>5}")
    print("-"*70)
    for r in rows[:30]:
        print(f"{r['class_name']:<40} {r['total_slots']:>6} {r['named_slots']:>6} {r['generic_slots']:>8} {r['coverage_pct']:>4}%")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
