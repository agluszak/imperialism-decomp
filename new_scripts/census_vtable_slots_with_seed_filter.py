#!/usr/bin/env python3
"""
Census vtable slots on a filtered class family selected by seed slot targets.

This is used to isolate TControl/UI-family vtables from the full g_vtblT* set
before deriving slot semantics for ambiguous base slots.

Usage:
  .venv/bin/python new_scripts/census_vtable_slots_with_seed_filter.py \
    --slots 32,33,39,81,84,87 \
    --seed-slot-target 71:thunk_BeginMouseCaptureAndStartRepeatTimer \
    --seed-slot-target 83:thunk_PaintVisibleChildrenIntersectingClipRect \
    --seed-slot-target 86:thunk_DispatchUiMouseMoveToChildren \
    --seed-slot-target 88:DispatchUiMouseEventToChildrenOrSelf \
    --seed-match-mode any \
    --out-vtbls-csv tmp_decomp/control_family_vtbls.csv \
    --out-summary-csv tmp_decomp/control_family_slot_summary.csv \
    --out-targets-csv tmp_decomp/control_family_slot_targets.csv
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


def parse_seed(spec: str) -> tuple[int, str]:
    if ":" not in spec:
        raise ValueError(f"invalid --seed-slot-target: {spec!r}; expected <slot>:<target_name>")
    s, t = spec.split(":", 1)
    return int(s.strip(), 10), t.strip()


def is_canonical_vtbl_symbol(name: str) -> bool:
    if not name.startswith("g_vtblT"):
        return False
    if "_Slot" in name or "Candidate_" in name or "Family_" in name:
        return False
    return True


def target_name_at_slot(program, fm, mem, af, vtbl_addr: int, slot_idx: int) -> tuple[str, int]:
    slot_addr_i = vtbl_addr + slot_idx * 4
    ptr_i = mem.getInt(af.getAddress(f"0x{slot_addr_i:08x}")) & 0xFFFFFFFF
    if ptr_i == 0:
        return "<null>", ptr_i
    fn = fm.getFunctionAt(af.getAddress(f"0x{ptr_i:08x}"))
    if fn is None:
        return f"<no-fn@0x{ptr_i:08x}>", ptr_i
    return fn.getName(), ptr_i


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slots", required=True, help="Comma-separated slot indices to census")
    ap.add_argument(
        "--seed-slot-target",
        action="append",
        default=[],
        help="Seed matcher in form <slot_idx>:<target_name>. Can repeat.",
    )
    ap.add_argument(
        "--seed-match-mode",
        choices=["any", "all"],
        default="any",
        help="Whether any or all seed rules must match for vtable inclusion",
    )
    ap.add_argument("--top", type=int, default=12, help="Top targets to print per slot")
    ap.add_argument("--out-vtbls-csv", default="tmp_decomp/seed_filtered_vtbls.csv")
    ap.add_argument("--out-summary-csv", default="tmp_decomp/seed_filtered_slot_summary.csv")
    ap.add_argument("--out-targets-csv", default="tmp_decomp/seed_filtered_slot_targets.csv")
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

    seeds: list[tuple[int, str]] = []
    for raw in args.seed_slot_target:
        seed = parse_seed(raw)
        seeds.append(seed)
    if not seeds:
        print("[error] provide at least one --seed-slot-target")
        return 1

    root = Path(args.project_root).resolve()

    out_vtbls = Path(args.out_vtbls_csv)
    if not out_vtbls.is_absolute():
        out_vtbls = root / out_vtbls
    out_summary = Path(args.out_summary_csv)
    if not out_summary.is_absolute():
        out_summary = root / out_summary
    out_targets = Path(args.out_targets_csv)
    if not out_targets.is_absolute():
        out_targets = root / out_targets

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    selected_vtbls: list[dict[str, str]] = []
    slot_target_counts: dict[int, Counter[str]] = defaultdict(Counter)
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
        vtbls = sorted(set(vtbls), key=lambda x: (x[0], x[1]))

        for vtbl_name, vtbl_addr in vtbls:
            seed_results = []
            seed_observed = []
            for seed_slot, seed_target in seeds:
                try:
                    observed, ptr_i = target_name_at_slot(
                        program, fm, mem, af, vtbl_addr, seed_slot
                    )
                except Exception:
                    observed = "<unread>"
                    ptr_i = 0
                matched = observed == seed_target
                seed_results.append(matched)
                seed_observed.append((seed_slot, seed_target, observed, ptr_i))

            if args.seed_match_mode == "all":
                include = all(seed_results)
            else:
                include = any(seed_results)
            if not include:
                continue

            matched_count = sum(1 for x in seed_results if x)
            selected_vtbls.append(
                {
                    "vtbl_name": vtbl_name,
                    "vtbl_addr": f"0x{vtbl_addr:08x}",
                    "seed_match_count": str(matched_count),
                    "seed_observed": ";".join(
                        f"{slot}:{expect}->{obs}@0x{ptr_i:08x}"
                        for slot, expect, obs, ptr_i in seed_observed
                    ),
                }
            )

            for slot_idx in slots:
                try:
                    target_name, ptr_i = target_name_at_slot(
                        program, fm, mem, af, vtbl_addr, slot_idx
                    )
                except Exception:
                    target_name = "<unread>"
                    ptr_i = 0
                slot_target_counts[slot_idx][target_name] += 1
                key = (slot_idx, target_name)
                if len(slot_target_samples[key]) < 8:
                    slot_target_samples[key].append(f"{vtbl_name}@0x{ptr_i:08x}")

    selected_vtbls.sort(
        key=lambda r: (-int(r["seed_match_count"]), r["vtbl_name"], r["vtbl_addr"])
    )
    summary_rows = []
    targets_rows = []
    for slot_idx in slots:
        counts = slot_target_counts.get(slot_idx, Counter())
        total = sum(counts.values())
        unique = len(counts)
        top_target = ""
        top_count = 0
        second_target = ""
        second_count = 0
        most = counts.most_common(2)
        if len(most) >= 1:
            top_target, top_count = most[0]
        if len(most) >= 2:
            second_target, second_count = most[1]
        summary_rows.append(
            {
                "slot_idx": str(slot_idx),
                "slot_off": f"0x{slot_idx * 4:04x}",
                "selected_vtables": str(total),
                "unique_targets": str(unique),
                "top_target": top_target,
                "top_count": str(top_count),
                "second_target": second_target,
                "second_count": str(second_count),
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

    out_vtbls.parent.mkdir(parents=True, exist_ok=True)
    with out_vtbls.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["vtbl_name", "vtbl_addr", "seed_match_count", "seed_observed"]
        )
        w.writeheader()
        w.writerows(selected_vtbls)

    with out_summary.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_idx",
                "slot_off",
                "selected_vtables",
                "unique_targets",
                "top_target",
                "top_count",
                "second_target",
                "second_count",
            ],
        )
        w.writeheader()
        w.writerows(summary_rows)

    with out_targets.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["slot_idx", "slot_off", "target_name", "count", "sample_entries"],
        )
        w.writeheader()
        w.writerows(targets_rows)

    print(f"[seed] mode={args.seed_match_mode} rules={len(seeds)}")
    for slot_idx, target_name in seeds:
        print(f"  - slot {slot_idx} == {target_name}")
    print(f"[saved] vtbls={out_vtbls} rows={len(selected_vtbls)}")
    print(f"[saved] summary={out_summary} rows={len(summary_rows)}")
    print(f"[saved] targets={out_targets} rows={len(targets_rows)}")

    for row in summary_rows:
        print(
            f"slot {row['slot_idx']} off={row['slot_off']} selected={row['selected_vtables']} "
            f"top={row['top_target']}({row['top_count']}) "
            f"second={row['second_target']}({row['second_count']})"
        )
        counts = slot_target_counts.get(int(row["slot_idx"]), Counter())
        for target_name, count in counts.most_common(args.top):
            print(f"  {count:3d}  {target_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
