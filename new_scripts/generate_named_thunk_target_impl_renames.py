#!/usr/bin/env python3
"""
Generate target-function renames from strict thunk bridge shape:

  named_caller -> thunk_FUN_xxxxxxxx -> FUN_yyyyyyyy

Conservative gates:
  - thunk name starts with `thunk_FUN_`
  - thunk body is exactly one `JMP` to internal target function
  - target name starts with `FUN_`
  - exactly one non-generic caller function for the thunk
  - optional: thunk has exactly one total caller

Output CSV columns:
  address,new_name,comment,target_old_name,thunk_addr,thunk_name,caller_addr,caller_name,total_callers,named_callers

Usage:
  .venv/bin/python new_scripts/generate_named_thunk_target_impl_renames.py \
    --out-csv tmp_decomp/batchNN_named_thunk_target_impl_renames.csv
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


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
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


def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "Unknown"
    if s[0].isdigit():
        s = "_" + s
    return s


def is_generic_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def is_named_non_thunk(name: str) -> bool:
    if name.startswith("thunk_"):
        return False
    return not is_generic_name(name)


def single_jmp_target_function(fm, listing, thunk):
    ins_it = listing.getInstructions(thunk.getBody(), True)
    insns = []
    while ins_it.hasNext():
        insns.append(ins_it.next())
        if len(insns) > 2:
            break
    if len(insns) != 1:
        return None
    ins = insns[0]
    if str(ins.getMnemonicString()).upper() != "JMP":
        return None
    flows = ins.getFlows()
    if flows is None or len(flows) != 1:
        return None
    return fm.getFunctionAt(flows[0])


def ensure_unique_name(existing: set[str], desired: str, addr: int) -> str:
    if desired not in existing:
        return desired
    base = f"{desired}_At{addr:08x}"
    name = base
    idx = 2
    while name in existing:
        name = f"{base}_{idx}"
        idx += 1
    return name


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/named_thunk_target_impl_renames.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--addr-min",
        default="0x00400000",
        help="Function address min (inclusive)",
    )
    ap.add_argument(
        "--addr-max",
        default="0x006fffff",
        help="Function address max (inclusive)",
    )
    ap.add_argument(
        "--require-single-total-caller",
        action="store_true",
        help="Require exactly one total caller to the thunk (default: enabled)",
    )
    ap.add_argument(
        "--allow-multi-total-caller",
        action="store_true",
        help="Disable single-total-caller gate",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    require_single_total = True
    if args.allow_multi_total_caller:
        require_single_total = False
    elif args.require_single_total_caller:
        require_single_total = True

    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    out_csv = Path(args.out_csv)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    by_target = {}

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        existing_names = set()
        fit = fm.getFunctions(True)
        funcs = []
        while fit.hasNext():
            f = fit.next()
            funcs.append(f)
            existing_names.add(f.getName())

        reserved_names = set(existing_names)

        for thunk in funcs:
            thunk_name = thunk.getName()
            if not thunk_name.startswith("thunk_FUN_"):
                continue

            thunk_addr = thunk.getEntryPoint().getOffset() & 0xFFFFFFFF
            if thunk_addr < lo or thunk_addr > hi:
                continue

            target = single_jmp_target_function(fm, listing, thunk)
            if target is None:
                continue
            target_addr = target.getEntryPoint().getOffset() & 0xFFFFFFFF
            target_name = target.getName()
            if not target_name.startswith("FUN_"):
                continue

            refs_to = rm.getReferencesTo(af.getAddress(f"0x{thunk_addr:08x}"))
            total_callers = {}
            named_callers = {}
            for ref in refs_to:
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                caddr = caller.getEntryPoint().getOffset() & 0xFFFFFFFF
                cname = caller.getName()
                total_callers[(caddr, cname)] = caller
                if is_named_non_thunk(cname):
                    named_callers[(caddr, cname)] = caller

            if len(named_callers) != 1:
                continue
            if require_single_total and len(total_callers) != 1:
                continue

            caller_addr, caller_name = next(iter(named_callers.keys()))

            # Conservative, non-semantic naming: mark as implementation for named caller.
            desired = sanitize_symbol_name(f"{caller_name}_Impl")
            # Avoid repeated chain suffixes like *_Impl_Impl for second-order bridges.
            desired = re.sub(r"(?:_Impl)+$", "_Impl", desired)
            final = ensure_unique_name(reserved_names, desired, target_addr)

            row = {
                "address": f"0x{target_addr:08x}",
                "new_name": final,
                "comment": (
                    f"[ThunkBridge] promoted from {thunk_name} with single named caller "
                    f"{caller_name}@0x{caller_addr:08x}"
                ),
                "target_old_name": target_name,
                "thunk_addr": f"0x{thunk_addr:08x}",
                "thunk_name": thunk_name,
                "caller_addr": f"0x{caller_addr:08x}",
                "caller_name": caller_name,
                "total_callers": str(len(total_callers)),
                "named_callers": str(len(named_callers)),
            }

            # Deduplicate targets. Keep first deterministic pick.
            if row["address"] in by_target:
                continue
            by_target[row["address"]] = row
            reserved_names.add(final)

    rows = [by_target[k] for k in sorted(by_target.keys())]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "new_name",
                "comment",
                "target_old_name",
                "thunk_addr",
                "thunk_name",
                "caller_addr",
                "caller_name",
                "total_callers",
                "named_callers",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} range=0x{lo:08x}-0x{hi:08x} "
        f"require_single_total={require_single_total}"
    )
    for r in rows[:160]:
        print(
            f"{r['address']},{r['target_old_name']} -> {r['new_name']},"
            f"thunk={r['thunk_name']} caller={r['caller_name']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
