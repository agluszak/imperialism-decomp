#!/usr/bin/env python3
"""
Define a typed base UI-view vtable skeleton and propagate conservative slot metadata.

Focus slots:
  - +0x94  : resolver-style calls (returns pointer in many call paths)
  - +0x1ac : control update/dispatch helper
  - +0x1d0 : control notify/refresh helper
  - +0x1d4 : alternate control notify/refresh helper

Behavior:
  1) Creates/updates datatype skeletons in /imperialism/ui:
       - TUiViewBaseVtableSkeleton
       - TUiViewBaseSkeleton
  2) Finds g_vtbl* symbols that expose at least N valid slot targets.
  3) Adds slot labels at vtable+offset for readability.
  4) Adds conservative function comments and low-risk signature typing for
     generic slot targets.

Usage:
  .venv/bin/python new_scripts/apply_ui_base_vslot_skeleton.py
  .venv/bin/python new_scripts/apply_ui_base_vslot_skeleton.py --apply
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
MARKER = "[UiVTableSkeleton]"

DEFAULT_SLOTS = {
    0x94: "ResolveControlByTag",
    0x1AC: "InvokeControlAction",
    0x1D0: "NotifyControlStateChange",
    0x1D4: "NotifyControlSelectionChange",
}

KNOWN_SLOT_NAMES = {
    0x0C: "HandleDialogSlot0C",
    0x84: "HandleDialogSlot84",
    0x94: "ResolveControlByTag",
    0xA4: "SetControlActiveFlag",
    0xA8: "SetControlVisibleFlag",
    0x1AC: "InvokeControlAction",
    0x1D0: "NotifyControlStateChange",
    0x1D4: "NotifyControlSelectionChange",
}


@dataclass
class SlotHit:
    vtbl_name: str
    vtbl_addr: int
    slot_off: int
    slot_addr: int
    target_addr: int
    target_name: str


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def parse_slots_arg(raw: str) -> dict[int, str]:
    if not raw.strip():
        return dict(DEFAULT_SLOTS)
    out: dict[int, str] = {}
    for tok in raw.split(","):
        t = tok.strip()
        if not t:
            continue
        v = parse_hex(t)
        out[v] = KNOWN_SLOT_NAMES.get(v, f"Slot{v:04X}")
    return out


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def ensure_ui_skeleton_types(program, write: bool):
    from ghidra.program.model.data import (
        ArrayDataType,
        ByteDataType,
        CategoryPath,
        DataTypeConflictHandler,
        FunctionDefinitionDataType,
        IntegerDataType,
        ParameterDefinitionImpl,
        PointerDataType,
        StructureDataType,
        VoidDataType,
    )

    dtm = program.getDataTypeManager()
    cat = CategoryPath("/imperialism/ui")

    void_t = VoidDataType.dataType
    int_t = IntegerDataType.dataType
    void_ptr = PointerDataType(void_t)

    fd94 = FunctionDefinitionDataType(cat, "TUiViewSlot0094_ResolveControlByTag")
    fd94.setReturnType(void_ptr)
    fd94.setArguments(
        [
            ParameterDefinitionImpl("pThis", void_ptr, ""),
            ParameterDefinitionImpl("controlTag", int_t, ""),
        ]
    )

    fd1ac = FunctionDefinitionDataType(cat, "TUiViewSlot01AC_InvokeControlAction")
    fd1ac.setReturnType(void_t)
    fd1ac.setArguments(
        [
            ParameterDefinitionImpl("pThis", void_ptr, ""),
            ParameterDefinitionImpl("arg0", int_t, ""),
            ParameterDefinitionImpl("arg1", int_t, ""),
        ]
    )

    fd1d0 = FunctionDefinitionDataType(cat, "TUiViewSlot01D0_NotifyControlStateChange")
    fd1d0.setReturnType(void_t)
    fd1d0.setArguments(
        [
            ParameterDefinitionImpl("pThis", void_ptr, ""),
            ParameterDefinitionImpl("arg0", int_t, ""),
            ParameterDefinitionImpl("arg1", int_t, ""),
        ]
    )

    fd1d4 = FunctionDefinitionDataType(cat, "TUiViewSlot01D4_NotifyControlSelectionChange")
    fd1d4.setReturnType(void_t)
    fd1d4.setArguments(
        [
            ParameterDefinitionImpl("pThis", void_ptr, ""),
            ParameterDefinitionImpl("arg0", int_t, ""),
            ParameterDefinitionImpl("arg1", int_t, ""),
        ]
    )

    pfd94 = PointerDataType(fd94)
    pfd1ac = PointerDataType(fd1ac)
    pfd1d0 = PointerDataType(fd1d0)
    pfd1d4 = PointerDataType(fd1d4)

    vtbl = StructureDataType(cat, "TUiViewBaseVtableSkeleton", 0)
    vtbl.add(ArrayDataType(ByteDataType.dataType, 0x94, 1), "gap_0000", None)
    vtbl.add(pfd94, "slot_0094_ResolveControlByTag", None)
    vtbl.add(ArrayDataType(ByteDataType.dataType, 0x114, 1), "gap_0098", None)
    vtbl.add(pfd1ac, "slot_01AC_InvokeControlAction", None)
    vtbl.add(ArrayDataType(ByteDataType.dataType, 0x20, 1), "gap_01B0", None)
    vtbl.add(pfd1d0, "slot_01D0_NotifyControlStateChange", None)
    vtbl.add(pfd1d4, "slot_01D4_NotifyControlSelectionChange", None)

    p_vtbl = PointerDataType(vtbl)
    view = StructureDataType(cat, "TUiViewBaseSkeleton", 0)
    view.add(p_vtbl, "pVtable", None)

    created = 0
    if write:
        for dt in (fd94, fd1ac, fd1d0, fd1d4, vtbl, view):
            dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
            created += 1

    return {
        "created_or_updated": created,
        "void_ptr": void_ptr,
        "int_t": int_t,
        "void_t": void_t,
    }


def iter_symbols(st):
    it = st.getSymbolIterator()
    while it.hasNext():
        yield it.next()


def is_generic_name(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("Cluster_")


def collect_slot_hits(
    program,
    min_slots_per_vtbl: int,
    include_vtbl_name_re: str,
    exclude_vtbl_name_re: str,
    slots: dict[int, str],
):
    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    all_hits: list[SlotHit] = []
    by_vtbl: dict[tuple[str, int], list[SlotHit]] = {}

    by_addr_names: dict[int, set[str]] = {}
    inc_re = re.compile(include_vtbl_name_re) if include_vtbl_name_re else None
    exc_re = re.compile(exclude_vtbl_name_re) if exclude_vtbl_name_re else None

    for sym in iter_symbols(st):
        name = sym.getName()
        if not name.startswith("g_vtbl"):
            continue
        # Avoid alias/derived labels that are themselves per-slot expansions.
        if "_Slot" in name:
            continue
        if inc_re is not None and inc_re.search(name) is None:
            continue
        if exc_re is not None and exc_re.search(name) is not None:
            continue
        addr_int = parse_hex(str(sym.getAddress()))
        by_addr_names.setdefault(addr_int, set()).add(name)

    def pick_canonical_vtbl_name(names: set[str]) -> str:
        def score(n: str):
            penalty = 0
            if "_Slot" in n:
                penalty += 100
            if "Candidate_" in n:
                penalty += 50
            if "Root" in n:
                penalty -= 10
            if n.startswith("g_vtblT"):
                penalty -= 5
            return (penalty, len(n), n)

        return sorted(names, key=score)[0]

    for addr_int, names in sorted(by_addr_names.items()):
        name = pick_canonical_vtbl_name(names)
        hits: list[SlotHit] = []
        for off in slots:
            slot_addr_int = addr_int + off
            try:
                ptr_val = mem.getInt(af.getAddress(f"0x{slot_addr_int:08x}")) & 0xFFFFFFFF
            except Exception:
                continue
            target_fn = fm.getFunctionAt(af.getAddress(f"0x{ptr_val:08x}"))
            if target_fn is None:
                continue
            if parse_hex(str(target_fn.getEntryPoint())) != ptr_val:
                continue
            hit = SlotHit(
                vtbl_name=name,
                vtbl_addr=addr_int,
                slot_off=off,
                slot_addr=slot_addr_int,
                target_addr=ptr_val,
                target_name=target_fn.getName(),
            )
            hits.append(hit)

        if len(hits) < min_slots_per_vtbl:
            continue
        by_vtbl[(name, addr_int)] = hits
        all_hits.extend(hits)

    return by_vtbl, all_hits


def build_signature_plan(program, all_hits: list[SlotHit]):
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    per_func_slot: dict[int, set[int]] = {}
    for h in all_hits:
        per_func_slot.setdefault(h.target_addr, set()).add(h.slot_off)

    plan = []
    for faddr, slots in sorted(per_func_slot.items()):
        if len(slots) != 1:
            continue
        slot = next(iter(slots))
        f = fm.getFunctionAt(af.getAddress(f"0x{faddr:08x}"))
        if f is None:
            continue
        if f.getName().startswith("thunk_"):
            continue
        pcount = f.getParameterCount()
        if slot == 0x94 and pcount > 1:
            continue
        if slot in (0x1AC, 0x1D0, 0x1D4) and pcount > 2:
            continue
        sig_txt = str(f.getSignature())
        should_type = is_generic_name(f.getName()) or ("undefined" in sig_txt.lower())
        plan.append((f, slot, should_type))
    return plan


def apply_slot_labels(program, by_vtbl: dict[tuple[str, int], list[SlotHit]], slots: dict[int, str]):
    from ghidra.program.model.symbol import SourceType

    st = program.getSymbolTable()
    af = program.getAddressFactory().getDefaultAddressSpace()

    ok = 0
    skip = 0
    fail = 0
    for (vtbl_name, _vtbl_addr), hits in by_vtbl.items():
        for h in hits:
            slot_label = f"{vtbl_name.replace('g_vtbl', 'g_vslot', 1)}_Slot{h.slot_off:04X}_{slots[h.slot_off]}"
            a = af.getAddress(f"0x{h.slot_addr:08x}")
            names = {s.getName() for s in st.getSymbols(a)}
            if slot_label in names:
                skip += 1
                continue
            try:
                st.createLabel(a, slot_label, SourceType.USER_DEFINED)
                ok += 1
            except Exception:
                fail += 1
    return ok, skip, fail


def apply_function_comments_and_signatures(program, plan, slots: dict[int, str]):
    from ghidra.program.model.data import IntegerDataType, PointerDataType, VoidDataType
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType

    int_t = IntegerDataType.dataType
    void_t = VoidDataType.dataType
    void_ptr = PointerDataType(void_t)

    typed = 0
    typed_skip = 0
    comment_ok = 0
    comment_skip = 0
    type_fail = 0
    for f, slot, should_type in plan:
        line = (
            f"{MARKER} dispatch target for vtable slot +0x{slot:04x} "
            f"({slots[slot]})."
        )
        old_cmt = f.getComment() or ""
        if line in old_cmt:
            comment_skip += 1
        else:
            f.setComment((old_cmt + "\n" + line).strip() if old_cmt else line)
            comment_ok += 1

        if not should_type:
            typed_skip += 1
            continue

        try:
            old_sig = str(f.getSignature())
            pcount = f.getParameterCount()
            params = []
            if slot == 0x94:
                if pcount == 1:
                    params = [ParameterImpl("controlTag", int_t, program, SourceType.USER_DEFINED)]
                f.setReturnType(void_ptr, SourceType.USER_DEFINED)
            elif slot in (0x1AC, 0x1D0, 0x1D4):
                if pcount >= 1:
                    params.append(ParameterImpl("arg0", int_t, program, SourceType.USER_DEFINED))
                if pcount >= 2:
                    params.append(ParameterImpl("arg1", int_t, program, SourceType.USER_DEFINED))
                f.setReturnType(void_t, SourceType.USER_DEFINED)
            else:
                typed_skip += 1
                continue

            f.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                True,
                SourceType.USER_DEFINED,
                params,
            )
            if str(f.getSignature()) == old_sig:
                typed_skip += 1
            else:
                typed += 1
        except Exception:
            type_fail += 1

    return {
        "typed": typed,
        "typed_skip": typed_skip,
        "type_fail": type_fail,
        "comment_ok": comment_ok,
        "comment_skip": comment_skip,
    }


def write_report(path: Path, all_hits: list[SlotHit], slots: dict[int, str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(
            [
                "vtbl_name",
                "vtbl_addr",
                "slot_off",
                "slot_addr",
                "slot_name",
                "target_addr",
                "target_name",
            ]
        )
        for h in all_hits:
            wr.writerow(
                [
                    h.vtbl_name,
                    f"0x{h.vtbl_addr:08x}",
                    f"0x{h.slot_off:04x}",
                    f"0x{h.slot_addr:08x}",
                    slots[h.slot_off],
                    f"0x{h.target_addr:08x}",
                    h.target_name,
                ]
            )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write labels/comments/signatures")
    ap.add_argument("--min-slots-per-vtbl", type=int, default=2)
    ap.add_argument(
        "--slots",
        default="",
        help="Comma-separated slot offsets (hex). Empty=default key slots.",
    )
    ap.add_argument(
        "--include-vtbl-name-re",
        default="",
        help="Optional regex: only vtable symbols with matching names are scanned",
    )
    ap.add_argument(
        "--exclude-vtbl-name-re",
        default="",
        help="Optional regex: matching vtable symbols are skipped",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/ui_base_vslot_skeleton_report.csv",
        help="Output CSV with discovered vtable-slot targets",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)
    slots = parse_slots_arg(args.slots)
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        if not args.apply:
            type_info = ensure_ui_skeleton_types(program, write=False)
            by_vtbl, all_hits = collect_slot_hits(
                program,
                args.min_slots_per_vtbl,
                args.include_vtbl_name_re,
                args.exclude_vtbl_name_re,
                slots,
            )
            plan = build_signature_plan(program, all_hits)

            write_report(out_csv, all_hits, slots)

            unique_vtbl = len(by_vtbl)
            unique_targets = len({h.target_addr for h in all_hits})
            per_slot = {off: len({h.target_addr for h in all_hits if h.slot_off == off}) for off in slots}
            print(f"[types] created_or_updated={type_info['created_or_updated']}")
            print(
                f"[scan] vtables={unique_vtbl} slot_hits={len(all_hits)} "
                f"unique_targets={unique_targets}"
            )
            for off in sorted(slots):
                print(f"  slot+0x{off:04x} {slots[off]} targets={per_slot[off]}")
            print(f"[plan] typed_target_candidates={len(plan)}")
            for f, slot, should_type in plan[:60]:
                print(
                    f"  0x{parse_hex(str(f.getEntryPoint())):08x} {f.getName()} "
                    f"slot=0x{slot:04x} should_type={int(bool(should_type))} "
                    f"sig={f.getSignature()}"
                )
            if len(plan) > 60:
                print(f"  ... ({len(plan) - 60} more)")
            print(
                f"[filter] include={args.include_vtbl_name_re or '<none>'} "
                f"exclude={args.exclude_vtbl_name_re or '<none>'}"
            )
            print(f"[slots] {','.join(f'0x{x:04x}' for x in sorted(slots))}")
            print(f"[report] {out_csv}")
            print("[dry-run] pass --apply to write labels/comments/signatures")
            return 0

        tx = program.startTransaction("Apply UI base vslot skeleton")
        try:
            type_info = ensure_ui_skeleton_types(program, write=True)
            by_vtbl, all_hits = collect_slot_hits(
                program,
                args.min_slots_per_vtbl,
                args.include_vtbl_name_re,
                args.exclude_vtbl_name_re,
                slots,
            )
            plan = build_signature_plan(program, all_hits)
            write_report(out_csv, all_hits, slots)
            lbl_ok, lbl_skip, lbl_fail = apply_slot_labels(program, by_vtbl, slots)
            sig = apply_function_comments_and_signatures(program, plan, slots)
        finally:
            program.endTransaction(tx, True)

        unique_vtbl = len(by_vtbl)
        unique_targets = len({h.target_addr for h in all_hits})
        per_slot = {off: len({h.target_addr for h in all_hits if h.slot_off == off}) for off in slots}
        print(f"[types] created_or_updated={type_info['created_or_updated']}")
        print(
            f"[scan] vtables={unique_vtbl} slot_hits={len(all_hits)} "
            f"unique_targets={unique_targets}"
        )
        for off in sorted(slots):
            print(f"  slot+0x{off:04x} {slots[off]} targets={per_slot[off]}")
        print(f"[plan] typed_target_candidates={len(plan)}")
        print(
            f"[filter] include={args.include_vtbl_name_re or '<none>'} "
            f"exclude={args.exclude_vtbl_name_re or '<none>'}"
        )
        print(f"[slots] {','.join(f'0x{x:04x}' for x in sorted(slots))}")
        print(f"[report] {out_csv}")

        program.save("apply ui base vslot skeleton", None)
        print(
            f"[done] labels_ok={lbl_ok} labels_skip={lbl_skip} labels_fail={lbl_fail} "
            f"comments_ok={sig['comment_ok']} comments_skip={sig['comment_skip']} "
            f"typed={sig['typed']} typed_skip={sig['typed_skip']} type_fail={sig['type_fail']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
