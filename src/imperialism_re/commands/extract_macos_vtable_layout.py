#!/usr/bin/env python3
"""
Extract per-class vtable slot order from the macOS binary.

Primary path:
  - decompile all constructors for each class
  - find STORE ops writing vtable pointers to param0+offset
  - resolve candidates (including LOAD-indirect pointers)
  - pick best constructor/candidate by contiguous method slot run length

Fallback path:
  - dense data-reference cluster over class methods
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.decompiler import (
    _get_passthrough_opcodes,
    collect_param0_varnodes,
    create_configured_decompiler,
    decompile_function,
)
from imperialism_re.core.ghidra_session import open_program_path


def _read_be_ptr(mem, addr_obj) -> int | None:
    try:
        buf = bytearray(4)
        cnt = mem.getBytes(addr_obj, buf)
        if cnt < 4:
            return None
        return int.from_bytes(buf, "big") & 0xFFFFFFFF
    except Exception:
        return None


def _safe_addr(af, value: int):
    if value < 0 or value > 0xFFFFFFFF:
        return None
    try:
        return af.getAddress(f"{value:08x}")
    except Exception:
        return None


def _resolve_slot_method_addr(mem, af, slot_ptr: int, addr_to_method: dict[int, str]) -> int | None:
    slot_ptr &= 0xFFFFFFFF
    if slot_ptr in addr_to_method:
        return slot_ptr
    # PowerPC function-descriptor style indirection: slot -> descriptor -> code ptr.
    desc_addr = _safe_addr(af, slot_ptr)
    if desc_addr is None:
        return None
    code_ptr = _read_be_ptr(mem, desc_addr)
    if code_ptr is None:
        return None
    code_ptr &= 0xFFFFFFFF
    if code_ptr in addr_to_method:
        return code_ptr
    return None


def _get_param0_offset(vn, param0_vn: set, PcodeOp, visited=None, depth: int = 0) -> int | None:
    if visited is None:
        visited = set()
    uid = id(vn)
    if uid in visited or depth > 10:
        return None
    visited.add(uid)
    if vn in param0_vn:
        return 0
    defn = vn.getDef()
    if defn is None:
        return None
    op = int(defn.getOpcode())
    passthrough = _get_passthrough_opcodes(PcodeOp)
    if op in passthrough:
        for i in range(defn.getNumInputs()):
            r = _get_param0_offset(defn.getInput(i), param0_vn, PcodeOp, visited, depth + 1)
            if r is not None:
                return r
        return None
    if op in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
        in0 = defn.getInput(0)
        in1 = defn.getInput(1)
        if in1 is not None and in1.isConstant():
            r = _get_param0_offset(in0, param0_vn, PcodeOp, visited, depth + 1)
            if r is not None:
                return r + int(in1.getOffset())
        if in0 is not None and in0.isConstant():
            r = _get_param0_offset(in1, param0_vn, PcodeOp, visited, depth + 1)
            if r is not None:
                return r + int(in0.getOffset())
    return None


def _resolve_val_to_addr(
    vn,
    PcodeOp,
    mem,
    af,
    visited: set[int] | None = None,
    depth: int = 0,
) -> int | None:
    if vn is None:
        return None
    if visited is None:
        visited = set()
    uid = id(vn)
    if uid in visited or depth > 10:
        return None
    visited.add(uid)

    try:
        if vn.isAddress() or vn.isConstant():
            return int(vn.getOffset()) & 0xFFFFFFFF
    except Exception:
        pass

    defn = vn.getDef()
    if defn is None:
        return None
    op = int(defn.getOpcode())
    passthrough = _get_passthrough_opcodes(PcodeOp)

    if op in passthrough:
        for i in range(defn.getNumInputs()):
            out = _resolve_val_to_addr(defn.getInput(i), PcodeOp, mem, af, visited, depth + 1)
            if out is not None:
                return out
        return None

    if op in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
        in0 = _resolve_val_to_addr(defn.getInput(0), PcodeOp, mem, af, visited, depth + 1)
        in1 = _resolve_val_to_addr(defn.getInput(1), PcodeOp, mem, af, visited, depth + 1)
        if in0 is not None and in1 is not None:
            return (in0 + in1) & 0xFFFFFFFF
        return in0 if in0 is not None else in1

    if op == PcodeOp.PTRADD:
        base = _resolve_val_to_addr(defn.getInput(0), PcodeOp, mem, af, visited, depth + 1)
        idx = _resolve_val_to_addr(defn.getInput(1), PcodeOp, mem, af, visited, depth + 1)
        scale = _resolve_val_to_addr(defn.getInput(2), PcodeOp, mem, af, visited, depth + 1)
        if base is not None and idx is not None and scale is not None:
            return (base + (idx * scale)) & 0xFFFFFFFF
        return base

    if op == PcodeOp.LOAD:
        if defn.getNumInputs() < 2:
            return None
        ptr_addr = _resolve_val_to_addr(defn.getInput(1), PcodeOp, mem, af, visited, depth + 1)
        if ptr_addr is None:
            return None
        addr_obj = _safe_addr(af, ptr_addr)
        if addr_obj is None:
            return None
        return _read_be_ptr(mem, addr_obj)

    return None


def _expand_candidate_addrs(candidate: int, mem, af) -> list[int]:
    out = [candidate & 0xFFFFFFFF]
    cur = candidate & 0xFFFFFFFF
    for _ in range(2):
        addr_obj = _safe_addr(af, cur)
        if addr_obj is None:
            break
        nxt = _read_be_ptr(mem, addr_obj)
        if nxt is None or nxt == 0:
            break
        nxt &= 0xFFFFFFFF
        if nxt in out:
            break
        out.append(nxt)
        cur = nxt
    return out


def _find_method_start_slot(
    mem,
    af,
    vtable_addr: int,
    addr_to_method: dict[int, str],
    search_limit: int = 64,
) -> int | None:
    def read_slot(slot: int) -> int | None:
        addr_val = vtable_addr + slot * 4
        addr_obj = _safe_addr(af, addr_val)
        if addr_obj is None:
            return None
        raw = _read_be_ptr(mem, addr_obj)
        if raw is None:
            return None
        return _resolve_slot_method_addr(mem, af, raw, addr_to_method)

    for start in range(search_limit):
        first = read_slot(start)
        if first is None or first not in addr_to_method:
            continue
        second = read_slot(start + 1)
        third = read_slot(start + 2)
        if (second is not None and second in addr_to_method) or (
            third is not None and third in addr_to_method
        ):
            return start
    for start in range(search_limit):
        first = read_slot(start)
        if first is not None and first in addr_to_method:
            return start
    return None


def _measure_method_run(
    mem,
    af,
    vtable_addr: int,
    method_start_slot: int,
    addr_to_method: dict[int, str],
    max_slots: int = 512,
) -> int:
    count = 0
    for idx in range(max_slots):
        slot = method_start_slot + idx
        addr_obj = _safe_addr(af, vtable_addr + slot * 4)
        if addr_obj is None:
            break
        raw = _read_be_ptr(mem, addr_obj)
        if raw is None:
            break
        ptr = _resolve_slot_method_addr(mem, af, raw, addr_to_method)
        if ptr is None:
            break
        count += 1
    return count


def _extract_layout_via_data_ref_cluster(
    class_name: str,
    class_methods: list[tuple[str, int]],
    rm,
    fm,
    af,
    cluster_gap_max: int,
    min_cluster_methods: int,
) -> list[dict[str, str]]:
    ref_map: dict[int, tuple[str, int]] = {}
    for method_name, method_addr in class_methods:
        refs = rm.getReferencesTo(af.getAddress(f"{method_addr:08x}"))
        for ref in refs:
            src = ref.getFromAddress()
            if fm.getFunctionContaining(src) is not None:
                continue
            src_int = src.getOffset() & 0xFFFFFFFF
            if src_int not in ref_map:
                ref_map[src_int] = (method_name, method_addr)
    if not ref_map:
        return []

    sorted_refs = sorted(ref_map.keys())
    clusters: list[list[int]] = []
    cur: list[int] = [sorted_refs[0]]
    for addr in sorted_refs[1:]:
        if addr - cur[-1] <= cluster_gap_max:
            cur.append(addr)
        else:
            clusters.append(cur)
            cur = [addr]
    clusters.append(cur)

    best_cluster: list[int] = []
    best_score: tuple[int, int] = (-1, -1)
    for cluster in clusters:
        uniq = len({ref_map[a][0] for a in cluster})
        span = cluster[-1] - cluster[0] if len(cluster) > 1 else 0
        score = (uniq, -span)
        if score > best_score:
            best_score = score
            best_cluster = cluster
    if not best_cluster:
        return []

    unique_method_hits = len({ref_map[a][0] for a in best_cluster})
    if unique_method_hits < min_cluster_methods:
        return []

    out: list[dict[str, str]] = []
    for slot, ref_addr in enumerate(best_cluster):
        method_name, method_addr = ref_map[ref_addr]
        out.append(
            {
                "class": class_name,
                "slot_index": slot,
                "method_name": method_name,
                "macos_addr": f"0x{method_addr:08x}",
                "layout_source": "fallback_data_ref_cluster",
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract per-class vtable slot order from macOS binary via constructor Pcode.",
    )
    ap.add_argument(
        "--macos-program-path",
        default="/Imperialism_macos",
        help="Ghidra program path for the macOS binary.",
    )
    ap.add_argument(
        "--macos-csv",
        default="tmp_decomp/macos_class_methods.csv",
        help="macOS class methods CSV.",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/macos_vtable_layout.csv",
        help="Output vtable layout CSV.",
    )
    ap.add_argument("--classes", default="", help="Optional comma-separated class filter.")
    ap.add_argument(
        "--debug-max-missing-diag",
        type=int,
        default=0,
        help="Print missing-class diagnostics for at most N classes.",
    )
    ap.add_argument(
        "--fallback-cluster-gap-max",
        type=int,
        default=0x120,
        help="Fallback cluster max address gap between consecutive refs.",
    )
    ap.add_argument(
        "--fallback-min-cluster-methods",
        type=int,
        default=6,
        help="Fallback minimum unique class methods in best cluster.",
    )
    ap.add_argument(
        "--ctor-max-per-class",
        type=int,
        default=0,
        help="Optional cap of constructors evaluated per class (0 = all).",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    macos_csv_path = Path(args.macos_csv)
    if not macos_csv_path.is_absolute():
        macos_csv_path = root / macos_csv_path
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    class_filter: set[str] = {x.strip() for x in args.classes.split(",") if x.strip()}

    addr_to_method: dict[int, str] = {}
    constructors_by_class: dict[str, list[int]] = defaultdict(list)
    class_methods: dict[str, list[tuple[str, int]]] = defaultdict(list)
    with macos_csv_path.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            class_name = row.get("class", "").strip()
            method = row.get("method", "").strip()
            addr_str = row.get("address", "").strip()
            if not class_name or not method or not addr_str:
                continue
            try:
                addr_int = int(addr_str, 16) & 0xFFFFFFFF
            except ValueError:
                continue
            addr_to_method[addr_int] = method
            class_methods[class_name].append((method, addr_int))
            if method == "__ct__":
                constructors_by_class[class_name].append(addr_int)

    if class_filter:
        constructors_by_class = {
            k: v for k, v in constructors_by_class.items() if k in class_filter
        }
    for cls in constructors_by_class:
        constructors_by_class[cls] = sorted(set(constructors_by_class[cls]))
        if args.ctor_max_per_class > 0:
            constructors_by_class[cls] = constructors_by_class[cls][: args.ctor_max_per_class]

    total_ctor_count = sum(len(v) for v in constructors_by_class.values())
    print(
        f"[macos_csv] methods={len(addr_to_method)} classes={len(class_methods)} "
        f"ctor_classes={len(constructors_by_class)} ctors={total_ctor_count}"
    )

    rows: list[dict[str, str]] = []
    class_coverage: dict[str, str] = {}
    missing_diag_printed = 0

    with open_program_path(root, args.macos_program_path) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        mem = program.getMemory()
        af = program.getAddressFactory().getDefaultAddressSpace()

        ifc = create_configured_decompiler(program, timeout=45)
        try:
            from ghidra.program.model.pcode import PcodeOp  # noqa: PLC0415

            for class_name in sorted(constructors_by_class.keys()):
                ctor_addrs = constructors_by_class[class_name]
                best_layout_rows: list[dict[str, str]] = []
                best_layout_key: tuple[int, int] = (-1, 0)  # run_len, negative ctor count tie-break

                for ctor_addr in ctor_addrs:
                    ctor_addr_obj = _safe_addr(af, ctor_addr)
                    if ctor_addr_obj is None:
                        continue
                    ctor_fn = fm.getFunctionAt(ctor_addr_obj)
                    if ctor_fn is None:
                        continue
                    res = decompile_function(ifc, ctor_fn, 45)
                    if res is None:
                        continue
                    high_fn = res.getHighFunction()
                    if high_fn is None:
                        continue

                    param0_vn = collect_param0_varnodes(high_fn, ctor_fn, PcodeOp)
                    best_for_ctor: tuple[int, int, int] | None = None  # run_len, vtbl_addr, start_slot

                    for op in high_fn.getPcodeOps():
                        if int(op.getOpcode()) != PcodeOp.STORE:
                            continue
                        inputs = op.getInputs()
                        if len(inputs) < 3:
                            continue
                        off = _get_param0_offset(inputs[1], param0_vn, PcodeOp)
                        if off is None:
                            continue
                        candidate = _resolve_val_to_addr(inputs[2], PcodeOp, mem, af)
                        if candidate is None or candidate == 0:
                            continue
                        for cand in _expand_candidate_addrs(candidate, mem, af):
                            method_start = _find_method_start_slot(
                                mem,
                                af,
                                cand,
                                addr_to_method,
                                search_limit=64,
                            )
                            if method_start is None:
                                continue
                            run_len = _measure_method_run(
                                mem,
                                af,
                                cand,
                                method_start,
                                addr_to_method,
                                max_slots=512,
                            )
                            if run_len <= 0:
                                continue
                            probe = (run_len, cand, method_start)
                            if best_for_ctor is None or probe[0] > best_for_ctor[0]:
                                best_for_ctor = probe

                    if best_for_ctor is None:
                        continue

                    run_len, vtable_addr, method_start_slot = best_for_ctor
                    ctor_rows: list[dict[str, str]] = []
                    for slot_index in range(run_len):
                        slot_addr_obj = _safe_addr(
                            af, vtable_addr + ((method_start_slot + slot_index) * 4)
                        )
                        if slot_addr_obj is None:
                            break
                        raw_slot_ptr = _read_be_ptr(mem, slot_addr_obj)
                        if raw_slot_ptr is None:
                            break
                        slot_ptr = _resolve_slot_method_addr(mem, af, raw_slot_ptr, addr_to_method)
                        if slot_ptr is None:
                            break
                        ctor_rows.append(
                            {
                                "class": class_name,
                                "slot_index": slot_index,
                                "method_name": addr_to_method[slot_ptr],
                                "macos_addr": f"0x{slot_ptr:08x}",
                                "layout_source": "ctor_vtable_store",
                            }
                        )
                    key = (len(ctor_rows), -ctor_addr)
                    if key > best_layout_key:
                        best_layout_key = key
                        best_layout_rows = ctor_rows

                if best_layout_rows:
                    rows.extend(best_layout_rows)
                    class_coverage[class_name] = f"ok_ctor:{len(best_layout_rows)}"
                    print(f"[ok] {class_name}: {len(best_layout_rows)} slots via constructors")
                    continue

                class_coverage[class_name] = "no_vtable_store"
                if missing_diag_printed < args.debug_max_missing_diag and ctor_addrs:
                    ctor_addr = ctor_addrs[0]
                    missing_diag_printed += 1
                    print(f"[diag] missing-vtable {class_name} ctor=0x{ctor_addr:08x}")
                    ctor_fn = fm.getFunctionAt(_safe_addr(af, ctor_addr))
                    if ctor_fn is not None:
                        res = decompile_function(ifc, ctor_fn, 30)
                        if res is not None and res.getHighFunction() is not None:
                            high_fn = res.getHighFunction()
                            param0_vn = collect_param0_varnodes(high_fn, ctor_fn, PcodeOp)
                            for op in high_fn.getPcodeOps():
                                if int(op.getOpcode()) != PcodeOp.STORE:
                                    continue
                                inputs = op.getInputs()
                                if len(inputs) < 3:
                                    continue
                                off = _get_param0_offset(inputs[1], param0_vn, PcodeOp)
                                if off is None:
                                    continue
                                candidate = _resolve_val_to_addr(inputs[2], PcodeOp, mem, af)
                                cand_s = f"0x{candidate:08x}" if candidate is not None else "None"
                                print(f"  [diag] STORE param0+{off:#x} candidate={cand_s}")

                fallback_rows = _extract_layout_via_data_ref_cluster(
                    class_name,
                    class_methods.get(class_name, []),
                    rm,
                    fm,
                    af,
                    args.fallback_cluster_gap_max,
                    args.fallback_min_cluster_methods,
                )
                if fallback_rows:
                    rows.extend(fallback_rows)
                    class_coverage[class_name] = f"ok_fallback:{len(fallback_rows)}"
                    print(f"[ok-fallback] {class_name}: {len(fallback_rows)} slots via data-ref cluster")
        finally:
            ifc.dispose()

    rows.sort(key=lambda r: (r["class"], int(r["slot_index"])))
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["class", "slot_index", "method_name", "macos_addr", "layout_source"],
        )
        w.writeheader()
        w.writerows(rows)

    total_classes = len({r["class"] for r in rows})
    ok_count = sum(1 for v in class_coverage.values() if v.startswith("ok"))
    fail_count = len(class_coverage) - ok_count
    source_counts = defaultdict(int)
    for row in rows:
        source_counts[row["layout_source"]] += 1

    print(f"[saved] {out_csv} rows={len(rows)} classes={total_classes}")
    print(f"[coverage] {ok_count} extracted, {fail_count} failed/skipped")
    print(
        "[sources] "
        + ", ".join(f"{k}={v}" for k, v in sorted(source_counts.items(), key=lambda kv: kv[0]))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
