#!/usr/bin/env python3
"""
Census vtable slot targets across canonical g_vtblT* classes.

Useful for turning generic slot names into evidence-backed behavior names by
observing dominant targets per slot across many classes.

Usage:
  .venv/bin/python new_scripts/census_vtable_slots_across_classes.py \
    --slots 32,33,38,39,43,45,65,68,71,81,82,83,84,85,86,87,88 \
    --out-summary-csv tmp_decomp/vslot_census_summary.csv \
    --out-targets-csv tmp_decomp/vslot_census_targets.csv
"""

from __future__ import annotations

import argparse
import csv
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


def parse_slots(text: str) -> list[int]:
    out = []
    for tok in text.split(","):
        tok = tok.strip()
        if not tok:
            continue
        out.append(int(tok, 10))
    return sorted(set(out))


def is_canonical_vtbl_symbol(name: str) -> bool:
    if not name.startswith("g_vtblT"):
        return False
    if "_Slot" in name or "Candidate_" in name or "Family_" in name:
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--slots",
        required=True,
        help="Comma-separated slot indices, e.g. 32,33,38",
    )
    ap.add_argument(
        "--top",
        type=int,
        default=10,
        help="Top targets to print per slot",
    )
    ap.add_argument(
        "--out-summary-csv",
        default="tmp_decomp/vslot_census_summary.csv",
        help="Per-slot summary output",
    )
    ap.add_argument(
        "--out-targets-csv",
        default="tmp_decomp/vslot_census_targets.csv",
        help="Per-slot/per-target counts output",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    slots = parse_slots(args.slots)
    if not slots:
        print("[error] no slots parsed")
        return 1

    root = Path(args.project_root).resolve()
    out_summary = Path(args.out_summary_csv)
    if not out_summary.is_absolute():
        out_summary = root / out_summary
    out_targets = Path(args.out_targets_csv)
    if not out_targets.is_absolute():
        out_targets = root / out_targets

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    slot_target_counts: dict[int, Counter[str]] = defaultdict(Counter)
    # key: (slot, target) -> sample entries "class@ptr"
    slot_target_samples: dict[tuple[int, str], list[str]] = defaultdict(list)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()

        vtbls: list[tuple[str, int]] = []
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            s = sit.next()
            name = s.getName()
            if not is_canonical_vtbl_symbol(name):
                continue
            try:
                addr_i = int(str(s.getAddress()), 16)
            except Exception:
                continue
            vtbls.append((name, addr_i))

        # Dedup by (name, addr).
        vtbls = sorted(set(vtbls), key=lambda x: (x[0], x[1]))

        for vtbl_name, vtbl_addr in vtbls:
            for slot_idx in slots:
                slot_addr_i = vtbl_addr + slot_idx * 4
                try:
                    ptr_i = mem.getInt(af.getAddress(f"0x{slot_addr_i:08x}")) & 0xFFFFFFFF
                except Exception:
                    target_name = "<unread>"
                    slot_target_counts[slot_idx][target_name] += 1
                    sample_key = (slot_idx, target_name)
                    if len(slot_target_samples[sample_key]) < 8:
                        slot_target_samples[sample_key].append(f"{vtbl_name}@<unread>")
                    continue

                if ptr_i == 0:
                    target_name = "<null>"
                    slot_target_counts[slot_idx][target_name] += 1
                    sample_key = (slot_idx, target_name)
                    if len(slot_target_samples[sample_key]) < 8:
                        slot_target_samples[sample_key].append(f"{vtbl_name}@0x00000000")
                    continue

                fn = fm.getFunctionAt(af.getAddress(f"0x{ptr_i:08x}"))
                if fn is None:
                    target_name = f"<no-fn@0x{ptr_i:08x}>"
                    ns_name = "Global"
                else:
                    target_name = fn.getName()
                    ns = fn.getParentNamespace()
                    ns_name = "Global" if ns is None else str(ns.getName())

                slot_target_counts[slot_idx][target_name] += 1
                sample_key = (slot_idx, target_name)
                if len(slot_target_samples[sample_key]) < 8:
                    slot_target_samples[sample_key].append(
                        f"{vtbl_name}@0x{ptr_i:08x}[{ns_name}]"
                    )

    summary_rows = []
    targets_rows = []
    for slot_idx in slots:
        counts = slot_target_counts.get(slot_idx, Counter())
        total = sum(counts.values())
        unique = len(counts)
        top_name = ""
        top_count = 0
        if counts:
            top_name, top_count = counts.most_common(1)[0]

        summary_rows.append(
            {
                "slot_idx": str(slot_idx),
                "slot_off": f"0x{slot_idx * 4:04x}",
                "total_vtables": str(total),
                "unique_targets": str(unique),
                "top_target": top_name,
                "top_count": str(top_count),
            }
        )

        for target_name, count in counts.most_common():
            samples = slot_target_samples.get((slot_idx, target_name), [])
            targets_rows.append(
                {
                    "slot_idx": str(slot_idx),
                    "slot_off": f"0x{slot_idx * 4:04x}",
                    "target_name": target_name,
                    "count": str(count),
                    "sample_entries": ";".join(samples),
                }
            )

    out_summary.parent.mkdir(parents=True, exist_ok=True)
    with out_summary.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_idx",
                "slot_off",
                "total_vtables",
                "unique_targets",
                "top_target",
                "top_count",
            ],
        )
        w.writeheader()
        w.writerows(summary_rows)

    with out_targets.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_idx",
                "slot_off",
                "target_name",
                "count",
                "sample_entries",
            ],
        )
        w.writeheader()
        w.writerows(targets_rows)

    print(f"[saved] summary={out_summary} rows={len(summary_rows)}")
    print(f"[saved] targets={out_targets} rows={len(targets_rows)}")
    for srow in summary_rows:
        slot_idx = int(srow["slot_idx"])
        print(
            f"\nslot {slot_idx} off={srow['slot_off']} total={srow['total_vtables']} "
            f"unique={srow['unique_targets']}"
        )
        counts = slot_target_counts.get(slot_idx, Counter())
        for name, cnt in counts.most_common(args.top):
            print(f"  {cnt:3d}  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
