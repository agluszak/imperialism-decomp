#!/usr/bin/env python3
"""
Generate rename CSV for generic functions uniquely owned by one class vtable slot.

Output CSV columns:
  address,new_name,comment

New-name format:
  <ClassName>_VtblSlotNN

Usage:
  .venv/bin/python new_scripts/generate_unique_vtable_slot_fun_renames.py [out_csv] [project_root]
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
VTBL_NAME_RE = re.compile(r"^g_vtbl(T[A-Za-z0-9_]+)$")
VTBL_SLOT_RE = re.compile(r"^g_vtbl_([A-Za-z0-9_]+)_Slot([0-9]+)$")


def parse_hex(text: str) -> int:
    t = text.strip()
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


def collect_vtable_anchors(program) -> dict[str, set[int]]:
    st = program.getSymbolTable()
    out: dict[str, set[int]] = defaultdict(set)
    it = st.getSymbolIterator()
    while it.hasNext():
        sym = it.next()
        name = sym.getName()

        m = VTBL_NAME_RE.match(name)
        if m:
            out[m.group(1)].add(parse_hex(str(sym.getAddress())))
            continue

        m = VTBL_SLOT_RE.match(name)
        if not m:
            continue
        tname = m.group(1)
        slot_idx = int(m.group(2))
        slot_addr = parse_hex(str(sym.getAddress()))
        base_addr = slot_addr - slot_idx * 4
        if base_addr >= 0:
            out[tname].add(base_addr)
    return out


def is_generic_name(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_")


def vtbl_slots(program, vtbl_addr: int, max_slots: int, max_hole_run: int):
    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    fm = program.getFunctionManager()
    holes = 0
    saw_valid = False

    for idx in range(max_slots):
        slot_addr = vtbl_addr + idx * 4
        try:
            ptr = mem.getInt(af.getAddress(f"0x{slot_addr:08x}")) & 0xFFFFFFFF
        except Exception:
            holes += 1
            if saw_valid and holes >= max_hole_run:
                break
            continue

        func = fm.getFunctionAt(af.getAddress(f"0x{ptr:08x}"))
        if func is None or parse_hex(str(func.getEntryPoint())) != ptr:
            holes += 1
            if saw_valid and holes >= max_hole_run:
                break
            continue

        saw_valid = True
        holes = 0
        yield idx, ptr, func


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "out_csv",
        nargs="?",
        default="tmp_decomp/unique_vtable_slot_fun_renames.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "project_root",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument("--max-slots", type=int, default=180)
    ap.add_argument("--max-hole-run", type=int, default=6)
    ap.add_argument("--min-targets-per-vtbl", type=int, default=4)
    args = ap.parse_args()

    out_csv = Path(args.out_csv)
    root = Path(args.project_root)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        fm = program.getFunctionManager()

        # Existing function names for collision avoidance.
        existing_names = set()
        itf = fm.getFunctions(True)
        while itf.hasNext():
            existing_names.add(itf.next().getName())

        owners: dict[int, set[tuple[str, int]]] = defaultdict(set)
        best_ref: dict[int, tuple[str, int]] = {}

        anchors = collect_vtable_anchors(program)
        for class_name, addrs in anchors.items():
            for vtbl_addr in sorted(addrs):
                entries = list(
                    vtbl_slots(
                        program,
                        vtbl_addr,
                        max_slots=args.max_slots,
                        max_hole_run=args.max_hole_run,
                    )
                )
                if len(entries) < args.min_targets_per_vtbl:
                    continue
                for slot_idx, tgt, _func in entries:
                    owners[tgt].add((class_name, slot_idx))
                    if tgt not in best_ref:
                        best_ref[tgt] = (class_name, slot_idx)

        proposals = []
        seen_new_names = set()
        for tgt, owner_set in sorted(owners.items()):
            if len(owner_set) != 1:
                continue
            class_name, slot_idx = next(iter(owner_set))
            func = fm.getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(f"0x{tgt:08x}"))
            if func is None:
                continue
            if not is_generic_name(func.getName()):
                continue

            new_name = f"{class_name}_VtblSlot{slot_idx:02d}"
            if new_name in existing_names or new_name in seen_new_names:
                # Keep name generation deterministic but avoid collisions.
                new_name = f"{class_name}_VtblSlot{slot_idx:02d}_{tgt:08x}"
            if new_name in existing_names or new_name in seen_new_names:
                continue
            seen_new_names.add(new_name)

            proposals.append(
                {
                    "address": f"0x{tgt:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[VtableSlot] Unique {class_name} owner, "
                        f"vtable slot {slot_idx}."
                    ),
                }
            )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(proposals)

    print(f"[saved] {out_csv} rows={len(proposals)}")
    for row in proposals[:120]:
        print(f"{row['address']},{row['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
