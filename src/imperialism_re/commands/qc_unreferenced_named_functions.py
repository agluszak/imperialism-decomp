#!/usr/bin/env python3
"""
QC: Find named functions with zero callers and zero data xrefs.
These may be dead code, missed function-pointer references, or analysis gaps.

Output CSV: address, namespace, name, calling_convention, caller_count, data_xref_count, total_xrefs
"""
from __future__ import annotations
import argparse, csv
from pathlib import Path
from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

GENERIC_PREFIXES = ("FUN_", "thunk_FUN_", "Cluster_", "DAT_", "PTR_",
                    "OrphanVtableAssignStub_", "OrphanRetStub_",
                    "OrphanLeaf_", "OrphanCallChain_",
                    "WrapperFor_FreeHeapBufferIfNotNull_At",
                    "WrapperFor_ftol_At",
                    "thunk_ForwardStructuredExceptionDispatchThroughFrameInfo_At",
                    "thunk_scalar_deleting_destructor_",
                    "NoOpPaddingStub_",
                    "FID_conflict:")

def is_generic(name: str) -> bool:
    for p in GENERIC_PREFIXES:
        if name.startswith(p):
            return True
    return False

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--min-address", default="0x00400000")
    ap.add_argument("--max-address", default="0x00700000")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()
    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    min_addr = int(args.min_address, 16)
    max_addr = int(args.max_address, 16)

    rows = []
    with open_program(root) as program:
        fm = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        global_ns = program.getGlobalNamespace()
        af = program.getAddressFactory().getDefaultAddressSpace()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < min_addr or ep >= max_addr:
                continue

            name = fn.getName()
            if is_generic(name):
                continue

            ns = fn.getParentNamespace()
            ns_name = "Global" if ns is None or ns == global_ns else ns.getName()

            # Count callers (code refs TO this function's entry)
            ep_addr = fn.getEntryPoint()
            caller_count = 0
            data_xref_count = 0
            refs = ref_mgr.getReferencesTo(ep_addr)
            for ref in refs:
                ref_type = str(ref.getReferenceType())
                if "CALL" in ref_type or "JUMP" in ref_type:
                    caller_count += 1
                elif "DATA" in ref_type or "READ" in ref_type:
                    data_xref_count += 1

            if caller_count == 0 and data_xref_count == 0:
                rows.append({
                    "address": f"0x{ep:08x}",
                    "namespace": ns_name,
                    "name": name,
                    "calling_convention": str(fn.getCallingConventionName()),
                    "caller_count": 0,
                    "data_xref_count": 0,
                    "total_xrefs": 0,
                })

    print(f"[unreferenced] {len(rows)} named functions with 0 xrefs")
    rows.sort(key=lambda r: (r["namespace"], r["name"]))

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["address","namespace","name","calling_convention","caller_count","data_xref_count","total_xrefs"])
        w.writeheader()
        w.writerows(rows)
    print(f"[saved] {out_csv} rows={len(rows)}")

    for r in rows[:40]:
        print(f"  {r['address']} [{r['namespace']}] {r['name']} ({r['calling_convention']})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
