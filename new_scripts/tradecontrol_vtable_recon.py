#!/usr/bin/env python3
"""
Build a TradeControl-focused vtable matrix and optional slot labels.

What this does:
1) Parses TradeControl virtual slot names from ui_widget_shared.h.
2) Resolves concrete class vtable roots (g_vtblT* symbols).
3) Dumps slot->target mappings for selected classes.
4) Emits:
   - matrix CSV
   - slot summary CSV
   - target ownership CSV
   - attach-candidate CSV (unique-owner class methods)
5) Optional: apply readable slot labels at vtable+slot addresses.

Usage:
  .venv/bin/python new_scripts/tradecontrol_vtable_recon.py
  .venv/bin/python new_scripts/tradecontrol_vtable_recon.py --apply-slot-labels
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
MARKER = "[TradeControlVtable]"


@dataclass
class SlotRow:
    class_name: str
    vtbl_symbol: str
    vtbl_addr: int
    slot_idx: int
    slot_off: int
    interface_method: str
    slot_addr: int
    target_addr: int | None
    target_name: str
    target_namespace: str
    target_signature: str
    target_callconv: str
    is_generic: int
    is_global: int


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def is_generic_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def sanitize_symbol(text: str) -> str:
    out = re.sub(r"[^0-9A-Za-z_]", "_", text)
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        out = "slot"
    return out


def parse_tradecontrol_virtual_slots(header_path: Path) -> list[str]:
    if not header_path.exists():
        return []
    text = header_path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"struct\s+TradeControl\s*\{(.*?)\n\};", text, flags=re.S)
    if not m:
        return []
    body = m.group(1)
    out: list[str] = []
    for ln in body.splitlines():
        line = ln.strip()
        if not line.startswith("virtual "):
            continue
        vm = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if not vm:
            continue
        out.append(vm.group(1))
    return out


def resolve_vtable_symbol_for_class(symbol_map: dict[str, list[tuple[str, int]]], class_name: str):
    exact_names = [f"g_vtbl{class_name}", f"g_vtbl_{class_name}"]
    for n in exact_names:
        if n in symbol_map and symbol_map[n]:
            # Keep deterministic pick.
            name, addr = sorted(symbol_map[n], key=lambda x: x[1])[0]
            return name, addr

    # Fallback: any g_vtbl* symbol containing class name.
    cands: list[tuple[str, int]] = []
    for n, vals in symbol_map.items():
        if not n.startswith("g_vtbl"):
            continue
        if class_name not in n:
            continue
        cands.extend(vals)
    if not cands:
        return None, None
    # Prefer shortest, then lowest address.
    cands.sort(key=lambda x: (len(x[0]), x[1], x[0]))
    return cands[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--classes",
        nargs="+",
        default=[
            "TAmtBar",
            "TIndustryAmtBar",
            "TRailAmtBar",
            "TShipAmtBar",
            "TTraderAmtBar",
            "TNumberedArrowButton",
            "THQButton",
            "TArmyPlacard",
            "TPlacard",
        ],
        help="Concrete classes to map against TradeControl slot interface",
    )
    ap.add_argument(
        "--header-path",
        default="/home/agluszak/code/personal/imperialism-decomp/include/game/ui_widget_shared.h",
        help="Path to ui_widget_shared.h containing struct TradeControl virtual list",
    )
    ap.add_argument(
        "--out-prefix",
        default="tmp_decomp/tradecontrol_vtable",
        help="Prefix for output files (without extension)",
    )
    ap.add_argument("--max-slots", type=int, default=128, help="Max slots to scan per vtable")
    ap.add_argument("--max-hole-run", type=int, default=8, help="Stop after N consecutive misses")
    ap.add_argument(
        "--apply-slot-labels",
        action="store_true",
        help="Write readable slot labels at vtable+offset addresses",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_prefix = Path(args.out_prefix)
    if not out_prefix.is_absolute():
        out_prefix = root / out_prefix
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    out_matrix = out_prefix.with_name(out_prefix.name + "_matrix.csv")
    out_slots = out_prefix.with_name(out_prefix.name + "_slot_summary.csv")
    out_targets = out_prefix.with_name(out_prefix.name + "_target_summary.csv")
    out_attach = out_prefix.with_name(out_prefix.name + "_attach_candidates.csv")

    interface_names = parse_tradecontrol_virtual_slots(Path(args.header_path))
    if interface_names:
        print(f"[slots] parsed TradeControl virtuals={len(interface_names)} from {args.header_path}")
    else:
        print("[slots] warning: failed to parse TradeControl virtual list; using slot-index fallback")

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[SlotRow] = []
    missing_classes: list[str] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        symbol_map: dict[str, list[tuple[str, int]]] = defaultdict(list)
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            s = sit.next()
            try:
                addr = parse_hex(str(s.getAddress()))
            except Exception:
                continue
            symbol_map[s.getName()].append((s.getName(), addr))

        class_vtbls: dict[str, tuple[str, int]] = {}
        for cls in args.classes:
            sym_name, sym_addr = resolve_vtable_symbol_for_class(symbol_map, cls)
            if sym_name is None or sym_addr is None:
                missing_classes.append(cls)
                continue
            class_vtbls[cls] = (sym_name, sym_addr)

        for cls in args.classes:
            if cls not in class_vtbls:
                continue
            vtbl_sym, vtbl_addr = class_vtbls[cls]
            holes = 0
            saw_any = False
            for slot_idx in range(args.max_slots):
                slot_off = slot_idx * 4
                slot_addr = vtbl_addr + slot_off
                iface_name = (
                    interface_names[slot_idx]
                    if slot_idx < len(interface_names)
                    else f"Slot{slot_off:04X}"
                )

                target_addr: int | None = None
                target_name = ""
                target_ns_name = ""
                target_sig = ""
                target_cc = ""
                is_generic = 0
                is_global = 1

                try:
                    ptr = mem.getInt(af.getAddress(f"0x{slot_addr:08x}")) & 0xFFFFFFFF
                    f = fm.getFunctionAt(af.getAddress(f"0x{ptr:08x}"))
                    if f is not None and parse_hex(str(f.getEntryPoint())) == ptr:
                        saw_any = True
                        holes = 0
                        target_addr = ptr
                        target_name = f.getName()
                        target_sig = str(f.getSignature())
                        target_cc = f.getCallingConventionName() or ""
                        pns = f.getParentNamespace()
                        if pns is None or pns == global_ns or pns.getName() == "Global":
                            target_ns_name = ""
                            is_global = 1
                        else:
                            target_ns_name = pns.getName()
                            is_global = 0
                        is_generic = 1 if is_generic_name(target_name) else 0
                    else:
                        holes += 1
                except Exception:
                    holes += 1

                rows.append(
                    SlotRow(
                        class_name=cls,
                        vtbl_symbol=vtbl_sym,
                        vtbl_addr=vtbl_addr,
                        slot_idx=slot_idx,
                        slot_off=slot_off,
                        interface_method=iface_name,
                        slot_addr=slot_addr,
                        target_addr=target_addr,
                        target_name=target_name,
                        target_namespace=target_ns_name,
                        target_signature=target_sig,
                        target_callconv=target_cc,
                        is_generic=is_generic,
                        is_global=is_global,
                    )
                )

                if saw_any and holes >= args.max_hole_run:
                    break

        if args.apply_slot_labels:
            tx = program.startTransaction("Apply TradeControl vtable slot labels")
            ok = skip = fail = 0
            try:
                for r in rows:
                    iface = sanitize_symbol(r.interface_method)
                    label = f"{r.vtbl_symbol}_Slot{r.slot_idx:03d}_{iface}"
                    addr_obj = af.getAddress(f"0x{r.slot_addr:08x}")
                    existing = list(st.getSymbols(addr_obj))
                    if any(s.getName() == label for s in existing):
                        skip += 1
                        continue
                    try:
                        st.createLabel(addr_obj, label, SourceType.USER_DEFINED)
                        ok += 1
                    except Exception:
                        fail += 1
                print(f"[apply-slot-labels] ok={ok} skip={skip} fail={fail}")
            finally:
                program.endTransaction(tx, True)
            program.save("apply tradecontrol vtable slot labels", None)

    # Matrix CSV
    with out_matrix.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "class_name",
                "vtbl_symbol",
                "vtbl_addr",
                "slot_idx",
                "slot_off",
                "interface_method",
                "slot_addr",
                "target_addr",
                "target_name",
                "target_namespace",
                "target_signature",
                "target_callconv",
                "is_generic",
                "is_global",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "class_name": r.class_name,
                    "vtbl_symbol": r.vtbl_symbol,
                    "vtbl_addr": f"0x{r.vtbl_addr:08x}",
                    "slot_idx": r.slot_idx,
                    "slot_off": f"0x{r.slot_off:04x}",
                    "interface_method": r.interface_method,
                    "slot_addr": f"0x{r.slot_addr:08x}",
                    "target_addr": f"0x{r.target_addr:08x}" if r.target_addr is not None else "",
                    "target_name": r.target_name,
                    "target_namespace": r.target_namespace,
                    "target_signature": r.target_signature,
                    "target_callconv": r.target_callconv,
                    "is_generic": r.is_generic,
                    "is_global": r.is_global,
                }
            )

    # Slot summary CSV
    slot_groups: dict[int, list[SlotRow]] = defaultdict(list)
    for r in rows:
        slot_groups[r.slot_idx].append(r)
    with out_slots.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "slot_idx",
                "slot_off",
                "interface_method",
                "present_class_count",
                "resolved_target_count",
                "distinct_target_count",
                "class_target_pairs",
            ],
        )
        w.writeheader()
        for slot_idx in sorted(slot_groups):
            rs = slot_groups[slot_idx]
            present_class_count = len({r.class_name for r in rs})
            resolved = [r for r in rs if r.target_addr is not None]
            distinct_targets = sorted({r.target_addr for r in resolved if r.target_addr is not None})
            class_pairs = []
            for r in sorted(rs, key=lambda x: x.class_name):
                if r.target_addr is None:
                    class_pairs.append(f"{r.class_name}:<none>")
                else:
                    class_pairs.append(f"{r.class_name}:{r.target_name}@0x{r.target_addr:08x}")
            iface = rs[0].interface_method if rs else f"Slot{slot_idx*4:04X}"
            w.writerow(
                {
                    "slot_idx": slot_idx,
                    "slot_off": f"0x{slot_idx*4:04x}",
                    "interface_method": iface,
                    "present_class_count": present_class_count,
                    "resolved_target_count": len(resolved),
                    "distinct_target_count": len(distinct_targets),
                    "class_target_pairs": ";".join(class_pairs),
                }
            )

    # Target ownership summary + attach candidates
    owners: dict[int, list[SlotRow]] = defaultdict(list)
    for r in rows:
        if r.target_addr is not None:
            owners[r.target_addr].append(r)

    target_rows = []
    attach_rows = []
    for taddr in sorted(owners):
        rs = owners[taddr]
        cls_set = sorted({r.class_name for r in rs})
        iface_set = sorted({r.interface_method for r in rs})
        slots = sorted({r.slot_idx for r in rs})
        sample = rs[0]
        unique_owner = cls_set[0] if len(cls_set) == 1 else ""
        target_rows.append(
            {
                "target_addr": f"0x{taddr:08x}",
                "target_name": sample.target_name,
                "target_namespace": sample.target_namespace,
                "target_signature": sample.target_signature,
                "target_callconv": sample.target_callconv,
                "owner_class_count": len(cls_set),
                "owner_classes": ";".join(cls_set),
                "owner_slots": ";".join(f"0x{s*4:04x}" for s in slots),
                "interface_methods": ";".join(iface_set),
                "is_generic": sample.is_generic,
                "is_global": sample.is_global,
                "unique_owner_class": unique_owner,
            }
        )
        if (
            unique_owner
            and sample.is_global == 1
            and sample.target_callconv == "__thiscall"
        ):
            primary = sorted(rs, key=lambda r: (r.slot_idx, r.class_name))[0]
            attach_rows.append(
                {
                    "address": f"0x{taddr:08x}",
                    "class_name": unique_owner,
                    "slot_idx": primary.slot_idx,
                    "slot_off": f"0x{primary.slot_off:04x}",
                    "interface_method": primary.interface_method,
                    "current_name": sample.target_name,
                    "current_namespace": sample.target_namespace or "Global",
                    "signature": sample.target_signature,
                    "reason": f"{MARKER} unique-owner slot target",
                }
            )

    with out_targets.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "target_addr",
                "target_name",
                "target_namespace",
                "target_signature",
                "target_callconv",
                "owner_class_count",
                "owner_classes",
                "owner_slots",
                "interface_methods",
                "is_generic",
                "is_global",
                "unique_owner_class",
            ],
        )
        w.writeheader()
        w.writerows(target_rows)

    with out_attach.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "class_name",
                "slot_idx",
                "slot_off",
                "interface_method",
                "current_name",
                "current_namespace",
                "signature",
                "reason",
            ],
        )
        w.writeheader()
        w.writerows(attach_rows)

    print(f"[done] classes_requested={len(args.classes)} classes_mapped={len(set(r.class_name for r in rows))}")
    if missing_classes:
        print(f"[missing-classes] {';'.join(missing_classes)}")
    print(f"[done] matrix={out_matrix} rows={len(rows)}")
    print(f"[done] slot_summary={out_slots} rows={len(slot_groups)}")
    print(f"[done] target_summary={out_targets} rows={len(target_rows)}")
    print(f"[done] attach_candidates={out_attach} rows={len(attach_rows)}")
    for r in attach_rows[:40]:
        print(
            f"{r['address']},{r['class_name']},slot={r['slot_off']},"
            f"{r['interface_method']},{r['current_name']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

