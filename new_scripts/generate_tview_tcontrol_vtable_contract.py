#!/usr/bin/env python3
"""
Generate a TView/TControl vtable contract from vtable matrix artifacts.

Inputs:
  - matrix CSV from tradecontrol_vtable_recon.py
    (columns include class_name, slot_idx, slot_off, interface_method,
     target_addr, target_name)

Outputs:
  - markdown contract
  - optional CSVs for TControl overrides and derived overrides

Usage:
  .venv/bin/python new_scripts/generate_tview_tcontrol_vtable_contract.py \
    --matrix-csv tmp_decomp/batch731_tcontrol_trade_vtbl_apply_matrix.csv \
    --out-md tview_tcontrol_vtable_contract.md
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def fmt_target(row: dict[str, str] | None) -> str:
    if not row:
        return "<none>"
    addr = (row.get("target_addr") or "").strip()
    name = (row.get("target_name") or "").strip()
    if not addr:
        return "<none>"
    if name:
        return f"{name}@{addr}"
    return addr


def is_resolved(row: dict[str, str] | None) -> bool:
    if not row:
        return False
    return bool((row.get("target_addr") or "").strip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix-csv", required=True)
    ap.add_argument("--base-class", default="TView")
    ap.add_argument("--mid-class", default="TControl")
    ap.add_argument(
        "--derived-classes",
        default="TAmtBar,TIndustryAmtBar,TRailAmtBar,TShipAmtBar,TTraderAmtBar,THQButton,TArmyPlacard,TPlacard",
    )
    ap.add_argument("--out-md", default="tview_tcontrol_vtable_contract.md")
    ap.add_argument("--out-tcontrol-overrides-csv", default="")
    ap.add_argument("--out-derived-overrides-csv", default="")
    args = ap.parse_args()

    matrix_csv = Path(args.matrix_csv)
    if not matrix_csv.exists():
        print(f"[error] missing matrix csv: {matrix_csv}")
        return 1

    derived_classes = [x.strip() for x in args.derived_classes.split(",") if x.strip()]
    all_classes = [args.base_class, args.mid_class] + derived_classes

    by_slot: dict[int, dict[str, dict[str, str]]] = defaultdict(dict)
    slot_off: dict[int, str] = {}
    slot_method: dict[int, str] = {}

    with matrix_csv.open("r", encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        for r in rd:
            cls = (r.get("class_name") or "").strip()
            if cls not in all_classes:
                continue
            try:
                idx = parse_int(r.get("slot_idx") or "")
            except Exception:
                continue
            by_slot[idx][cls] = r
            slot_off[idx] = (r.get("slot_off") or "").strip()
            slot_method[idx] = (r.get("interface_method") or "").strip() or f"Slot{idx}"

    slots = sorted(by_slot.keys())

    tcontrol_overrides: list[dict[str, str]] = []
    derived_overrides: list[dict[str, str]] = []
    unresolved_base_mid: list[dict[str, str]] = []
    non_gap_slots: list[dict[str, str]] = []

    base_resolved_slots = [
        idx for idx in slots if is_resolved(by_slot[idx].get(args.base_class))
    ]
    mid_resolved_slots = [
        idx for idx in slots if is_resolved(by_slot[idx].get(args.mid_class))
    ]
    base_max_resolved = max(base_resolved_slots) if base_resolved_slots else -1
    mid_max_resolved = max(mid_resolved_slots) if mid_resolved_slots else -1

    for idx in slots:
        base = by_slot[idx].get(args.base_class)
        mid = by_slot[idx].get(args.mid_class)
        off = slot_off.get(idx, "")
        method = slot_method.get(idx, f"Slot{idx}")
        base_has = is_resolved(base)
        mid_has = is_resolved(mid)

        derived_present = []
        for cls in derived_classes:
            d = by_slot[idx].get(cls)
            if is_resolved(d):
                derived_present.append(cls)
        has_derived = bool(derived_present)

        # Contract classification:
        # - "non-gap" categories represent intentional class-extension/abstract slots
        #   and should not be counted as unresolved noise.
        # - unresolved_base_mid keeps only potential real inconsistencies.
        classification = "aligned"
        if base_has and mid_has:
            classification = "aligned"
        elif (not base_has) and mid_has and has_derived:
            classification = "mid_or_derived_extension"
        elif (not base_has) and mid_has and idx > base_max_resolved:
            classification = "mid_extension_after_base_end"
        elif (not base_has) and (not mid_has) and has_derived:
            classification = "derived_only_extension"
        elif (not base_has) and (not mid_has) and idx > mid_max_resolved:
            classification = "trailing_inactive_after_mid_end"
        elif base_has and (not mid_has):
            classification = "mid_missing_base_set"
        else:
            classification = "base_mid_missing_unknown"

        if classification in {"mid_missing_base_set", "base_mid_missing_unknown"}:
            unresolved_base_mid.append(
                {
                    "slot_idx": str(idx),
                    "slot_off": off,
                    "interface_method": method,
                    "base_target": fmt_target(base),
                    "mid_target": fmt_target(mid),
                    "classification": classification,
                }
            )
        elif classification != "aligned":
            non_gap_slots.append(
                {
                    "slot_idx": str(idx),
                    "slot_off": off,
                    "interface_method": method,
                    "classification": classification,
                    "base_target": fmt_target(base),
                    "mid_target": fmt_target(mid),
                    "derived_present": ", ".join(derived_present) if derived_present else "<none>",
                }
            )

        base_addr = (base.get("target_addr") if base else "") or ""
        mid_addr = (mid.get("target_addr") if mid else "") or ""
        if base_addr and mid_addr and base_addr != mid_addr:
            tcontrol_overrides.append(
                {
                    "slot_idx": str(idx),
                    "slot_off": off,
                    "interface_method": method,
                    "base_target": fmt_target(base),
                    "mid_target": fmt_target(mid),
                }
            )

        class_deltas = []
        for cls in derived_classes:
            d = by_slot[idx].get(cls)
            daddr = ((d.get("target_addr") if d else "") or "").strip()
            if not daddr:
                continue
            if not mid_addr:
                class_deltas.append(f"{cls}:{fmt_target(d)} (mid=<none>)")
                continue
            if daddr != mid_addr:
                class_deltas.append(f"{cls}:{fmt_target(d)}")

        if class_deltas:
            derived_overrides.append(
                {
                    "slot_idx": str(idx),
                    "slot_off": off,
                    "interface_method": method,
                    "mid_target": fmt_target(mid),
                    "derived_overrides": "; ".join(class_deltas),
                }
            )

    out_md = Path(args.out_md)
    lines: list[str] = []
    lines.append("# TView/TControl VTable Contract")
    lines.append("")
    lines.append("## Sources")
    lines.append(f"- matrix: `{matrix_csv}`")
    lines.append(f"- base class: `{args.base_class}`")
    lines.append(f"- mid class: `{args.mid_class}`")
    lines.append(f"- derived classes: `{', '.join(derived_classes)}`")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- slots scanned: `{len(slots)}`")
    lines.append(f"- `{args.mid_class}` overrides vs `{args.base_class}`: `{len(tcontrol_overrides)}`")
    lines.append(f"- derived override slots vs `{args.mid_class}`: `{len(derived_overrides)}`")
    lines.append(f"- base max resolved slot: `{base_max_resolved}`")
    lines.append(f"- mid max resolved slot: `{mid_max_resolved}`")
    lines.append(f"- non-gap extension/abstract slots: `{len(non_gap_slots)}`")
    lines.append(f"- potential unresolved base/mid slots: `{len(unresolved_base_mid)}`")
    lines.append("")

    lines.append(f"## {args.mid_class} Overrides vs {args.base_class}")
    lines.append("| Slot | Offset | Interface Method | Base Target | Mid Target |")
    lines.append("|---|---|---|---|---|")
    if tcontrol_overrides:
        for r in tcontrol_overrides:
            lines.append(
                f"| `{r['slot_idx']}` | `{r['slot_off']}` | `{r['interface_method']}` | "
                f"`{r['base_target']}` | `{r['mid_target']}` |"
            )
    else:
        lines.append("| `<none>` |  |  |  |  |")
    lines.append("")

    lines.append(f"## Derived Overrides vs {args.mid_class}")
    lines.append("| Slot | Offset | Interface Method | Mid Target | Derived Overrides |")
    lines.append("|---|---|---|---|---|")
    if derived_overrides:
        for r in derived_overrides:
            lines.append(
                f"| `{r['slot_idx']}` | `{r['slot_off']}` | `{r['interface_method']}` | "
                f"`{r['mid_target']}` | `{r['derived_overrides']}` |"
            )
    else:
        lines.append("| `<none>` |  |  |  |  |")
    lines.append("")

    lines.append("## Non-gap Slot Classes (Intentional Base/Mid Absence)")
    lines.append("| Slot | Offset | Interface Method | Classification | Base Target | Mid Target | Derived Present |")
    lines.append("|---|---|---|---|---|---|---|")
    if non_gap_slots:
        for r in non_gap_slots:
            lines.append(
                f"| `{r['slot_idx']}` | `{r['slot_off']}` | `{r['interface_method']}` | "
                f"`{r['classification']}` | `{r['base_target']}` | `{r['mid_target']}` | "
                f"`{r['derived_present']}` |"
            )
    else:
        lines.append("| `<none>` |  |  |  |  |  |  |")
    lines.append("")

    lines.append(f"## Potential Unresolved Slots ({args.base_class}/{args.mid_class})")
    lines.append("| Slot | Offset | Interface Method | Classification | Base Target | Mid Target |")
    lines.append("|---|---|---|---|---|---|")
    if unresolved_base_mid:
        for r in unresolved_base_mid:
            lines.append(
                f"| `{r['slot_idx']}` | `{r['slot_off']}` | `{r['interface_method']}` | "
                f"`{r['classification']}` | `{r['base_target']}` | `{r['mid_target']}` |"
            )
    else:
        lines.append("| `<none>` |  |  |  |  |  |")
    lines.append("")

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] wrote {out_md}")

    if args.out_tcontrol_overrides_csv:
        out_csv = Path(args.out_tcontrol_overrides_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(
                fh,
                fieldnames=[
                    "slot_idx",
                    "slot_off",
                    "interface_method",
                    "base_target",
                    "mid_target",
                ],
            )
            w.writeheader()
            w.writerows(tcontrol_overrides)
        print(f"[done] wrote {out_csv} rows={len(tcontrol_overrides)}")

    if args.out_derived_overrides_csv:
        out_csv = Path(args.out_derived_overrides_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(
                fh,
                fieldnames=[
                    "slot_idx",
                    "slot_off",
                    "interface_method",
                    "mid_target",
                    "derived_overrides",
                ],
            )
            w.writeheader()
            w.writerows(derived_overrides)
        print(f"[done] wrote {out_csv} rows={len(derived_overrides)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
