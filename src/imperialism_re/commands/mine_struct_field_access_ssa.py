#!/usr/bin/env python3
"""
Mine struct field access via Pcode SSA varnode tracing.

Replaces the regex-based ``mine_struct_field_access`` with Pcode SSA analysis.
For each class, decompiles all namespace methods **and** their thunk/wrapper
targets, then scans LOAD/STORE Pcode ops whose address varnodes trace back to
param0 plus a constant offset.

Output CSV columns (compatible with ``apply_mined_struct_fields``):
  struct_path, class_name, offset, size, field_type, access_count, top_access,
  suggested_name, read_count, write_count

Usage:
  uv run impk mine_struct_field_access_ssa \
    --classes TradeControl --out-csv tmp_decomp/field_mine_ssa.csv

  uv run impk mine_struct_field_access_ssa \
    --top-n 20 --out-csv tmp_decomp/field_mine_ssa.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.decompiler import (
    _get_passthrough_opcodes,
    collect_param0_varnodes,
    create_configured_decompiler,
    decompile_function,
)
from imperialism_re.core.ghidra_session import open_program


# ---------------------------------------------------------------------------
# SSA offset tracing
# ---------------------------------------------------------------------------

def _trace_to_param0_plus_offset(
    vn,
    param0_varnodes: set,
    PcodeOp,
    max_depth: int = 8,
) -> int | None:
    """Walk backward through SSA def-chain to resolve *vn* as ``param0 + const``.

    Like ``trace_to_param0`` but returns the accumulated constant offset
    (or ``0`` for a direct param0 match).  Returns ``None`` if *vn* does
    not trace back to param0.
    """
    passthrough = _get_passthrough_opcodes(PcodeOp)
    # Stack entries: (varnode, accumulated_offset, depth)
    stack = [(vn, 0, 0)]
    visited: set[int] = set()
    while stack:
        cur, acc_offset, depth = stack.pop()
        if cur is None or depth > max_depth:
            continue
        uid = id(cur)
        if uid in visited:
            continue
        visited.add(uid)

        if cur in param0_varnodes:
            return acc_offset

        defn = cur.getDef()
        if defn is None:
            continue
        op = defn.getOpcode()

        if op in passthrough:
            for i in range(defn.getNumInputs()):
                stack.append((defn.getInput(i), acc_offset, depth + 1))
        elif op == PcodeOp.INT_ADD:
            in0 = defn.getInput(0)
            in1 = defn.getInput(1)
            if in1 is not None and in1.isConstant():
                stack.append((in0, acc_offset + int(in1.getOffset()), depth + 1))
            elif in0 is not None and in0.isConstant():
                stack.append((in1, acc_offset + int(in0.getOffset()), depth + 1))
        elif op == PcodeOp.PTRSUB:
            in0 = defn.getInput(0)
            in1 = defn.getInput(1)
            if in1 is not None and in1.isConstant():
                stack.append((in0, acc_offset + int(in1.getOffset()), depth + 1))

    return None


# ---------------------------------------------------------------------------
# Thunk / impl function collection (reused from mine_struct_field_access)
# ---------------------------------------------------------------------------

def _get_thunk_target(fn, fm):
    """If *fn* is a simple thunk, return its target."""
    body = fn.getBody()
    if body is None:
        return None
    if body.getNumAddresses() > 40:
        return None

    thunked = fn.getThunkedFunction(False)
    if thunked is not None:
        return thunked

    called = set()
    refs = fn.getCalledFunctions(None)
    if refs is not None:
        for callee in refs:
            called.add(callee)

    if len(called) == 1:
        return list(called)[0]
    return None


def _collect_impl_functions(cls_ns, fm, global_ns, max_depth=3):
    """Collect all class methods AND their thunk/wrapper target chains."""
    to_decompile = set()
    visited = set()

    fit = fm.getFunctions(True)
    while fit.hasNext():
        fn = fit.next()
        if fn.getParentNamespace() == cls_ns:
            to_decompile.add(fn)

    frontier = set(to_decompile)
    for _ in range(max_depth):
        next_frontier = set()
        for fn in frontier:
            if fn in visited:
                continue
            visited.add(fn)
            target = _get_thunk_target(fn, fm)
            if target is not None and target not in to_decompile:
                if target.getParentNamespace() == global_ns:
                    to_decompile.add(target)
                    next_frontier.add(target)
        frontier = next_frontier
        if not frontier:
            break

    return to_decompile


# ---------------------------------------------------------------------------
# Size inference from Ghidra datatype name
# ---------------------------------------------------------------------------

_TYPE_SIZE_HINTS = {
    "int": 4, "uint": 4, "undefined4": 4, "long": 4, "ulong": 4,
    "dword": 4, "uint32_t": 4, "int32_t": 4, "float": 4, "bool4": 4,
    "short": 2, "ushort": 2, "undefined2": 2, "word": 2,
    "uint16_t": 2, "int16_t": 2,
    "byte": 1, "undefined1": 1, "char": 1, "uint8_t": 1, "int8_t": 1,
    "bool": 1,
    "longlong": 8, "undefined8": 8, "double": 8,
    "uint64_t": 8, "int64_t": 8,
}


def _varnode_type_label(vn) -> str:
    """Best-effort type label for a varnode (used for access fingerprinting)."""
    try:
        high = vn.getHigh()
        if high is not None:
            dt = high.getDataType()
            if dt is not None:
                return dt.getDisplayName()
    except Exception:
        pass
    size = vn.getSize()
    return f"undefined{size}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Mine struct field access via Pcode SSA varnode tracing.",
    )
    ap.add_argument("--classes", nargs="*", default=[], help="Specific classes to mine")
    ap.add_argument("--top-n", type=int, default=0, help="Mine top N classes by anon field count")
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--max-methods", type=int, default=0, help="Max methods per class (0=all)")
    ap.add_argument("--verbose", action="store_true", help="Print per-method match details")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    with open_program(root) as program:
        from ghidra.program.model.data import Structure
        from ghidra.program.model.pcode import PcodeOp

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        # Determine target classes
        target_classes = set(args.classes)

        if args.top_n > 0:
            class_anon_counts = []
            it_cls = st.getClassNamespaces()
            while it_cls.hasNext():
                cls_ns = it_cls.next()
                cls_name = cls_ns.getName()
                for cat_prefix in ["/imperialism/classes/", "/", "/imperialism/types/"]:
                    dt = dtm.getDataType(f"{cat_prefix}{cls_name}")
                    if dt is not None and isinstance(dt, Structure):
                        anon = sum(1 for c in dt.getComponents() if not c.getFieldName())
                        class_anon_counts.append((cls_name, anon, f"{cat_prefix}{cls_name}"))
                        break

            class_anon_counts.sort(key=lambda x: x[1], reverse=True)
            for cls_name, anon, path in class_anon_counts[:args.top_n]:
                target_classes.add(cls_name)
                print(f"[top-n] {cls_name}: {anon} anon fields ({path})")

        if not target_classes:
            print("[error] no classes selected (use --classes or --top-n)")
            return 1

        # Build class → struct path map
        class_struct_paths: dict[str, tuple[str, object]] = {}
        for cls_name in sorted(target_classes):
            for cat_prefix in ["/imperialism/classes/", "/", "/imperialism/types/"]:
                dt = dtm.getDataType(f"{cat_prefix}{cls_name}")
                if dt is not None and isinstance(dt, Structure):
                    class_struct_paths[cls_name] = (f"{cat_prefix}{cls_name}", dt)
                    break
            if cls_name not in class_struct_paths:
                print(f"[skip] no struct found for {cls_name}")

        # Quality decompiler
        ifc = create_configured_decompiler(program)

        all_results = []
        total_methods = 0
        total_impl = 0

        for cls_name in sorted(class_struct_paths.keys()):
            struct_path, struct_dt = class_struct_paths[cls_name]

            # Get existing named fields
            existing_fields = {}
            for comp in struct_dt.getComponents():
                off = int(comp.getOffset())
                name = comp.getFieldName()
                if name:
                    existing_fields[off] = name

            # Find class namespace
            cls_ns = None
            it_cls = st.getClassNamespaces()
            while it_cls.hasNext():
                ns = it_cls.next()
                if ns.getName() == cls_name:
                    cls_ns = ns
                    break

            if cls_ns is None:
                continue

            # Collect methods AND their implementation targets
            all_fns = _collect_impl_functions(cls_ns, fm, global_ns)
            class_methods = [f for f in all_fns if f.getParentNamespace() == cls_ns]
            impl_fns = [f for f in all_fns if f.getParentNamespace() == global_ns]

            # Per-offset: Counter of "type_label:size" → count, plus read/write counts
            offset_accesses: dict[int, Counter] = defaultdict(Counter)
            offset_reads: dict[int, int] = defaultdict(int)
            offset_writes: dict[int, int] = defaultdict(int)

            method_count = len(class_methods)
            impl_count = len(impl_fns)
            decompiled = 0

            for fn in all_fns:
                if args.max_methods and decompiled >= args.max_methods:
                    break

                decompiled += 1
                res = decompile_function(ifc, fn)
                if res is None:
                    continue
                high_fn = res.getHighFunction()
                if high_fn is None:
                    continue

                param0_vns = collect_param0_varnodes(high_fn, fn, PcodeOp)
                if not param0_vns:
                    continue

                fn_hits = 0
                for op in high_fn.getPcodeOps():
                    opc = op.getOpcode()

                    if opc == PcodeOp.LOAD:
                        # LOAD space, addr, output
                        addr_vn = op.getInput(1)
                        offset = _trace_to_param0_plus_offset(addr_vn, param0_vns, PcodeOp)
                        if offset is not None and offset >= 0:
                            out_vn = op.getOutput()
                            size = out_vn.getSize() if out_vn is not None else 4
                            label = _varnode_type_label(out_vn) if out_vn is not None else f"undefined{size}"
                            offset_accesses[offset][f"{label}:{size}"] += 1
                            offset_reads[offset] += 1
                            fn_hits += 1

                    elif opc == PcodeOp.STORE:
                        # STORE space, addr, value
                        addr_vn = op.getInput(1)
                        offset = _trace_to_param0_plus_offset(addr_vn, param0_vns, PcodeOp)
                        if offset is not None and offset >= 0:
                            val_vn = op.getInput(2)
                            size = val_vn.getSize() if val_vn is not None else 4
                            label = _varnode_type_label(val_vn) if val_vn is not None else f"undefined{size}"
                            offset_accesses[offset][f"{label}:{size}"] += 1
                            offset_writes[offset] += 1
                            fn_hits += 1

                if args.verbose and fn_hits > 0:
                    ns_tag = "impl" if fn.getParentNamespace() == global_ns else "cls"
                    print(f"  [{ns_tag}] {fn.getName()}: {fn_hits} SSA field accesses")

            total_methods += method_count
            total_impl += impl_count
            print(f"[class] {cls_name}: {method_count} methods + {impl_count} impl fns, {len(offset_accesses)} offsets")

            # Generate field suggestions for unnamed offsets
            for offset in sorted(offset_accesses.keys()):
                if offset in existing_fields:
                    continue

                access_counts = offset_accesses[offset]
                total_access = sum(access_counts.values())
                top_access, _top_count = access_counts.most_common(1)[0]
                type_label, size_str = top_access.rsplit(":", 1)
                size = int(size_str)

                # Suggest name based on type
                type_lower = type_label.lower().rstrip("*").rstrip()
                is_ptr = "*" in type_label
                if is_ptr:
                    suggested = f"pField{offset:02x}"
                    field_type = "void*"
                elif type_lower in ("void", "undefined"):
                    suggested = f"pField{offset:02x}"
                    field_type = "void*"
                elif type_lower in ("float",):
                    suggested = f"fField{offset:02x}"
                    field_type = "float"
                elif size == 1:
                    suggested = f"field{offset:02x}"
                    field_type = "byte"
                elif size == 2:
                    suggested = f"field{offset:02x}"
                    field_type = "short"
                elif size == 8:
                    suggested = f"field{offset:02x}"
                    field_type = "longlong"
                else:
                    suggested = f"field{offset:02x}"
                    field_type = "int"

                all_results.append({
                    "struct_path": struct_path,
                    "class_name": cls_name,
                    "offset": f"0x{offset:02x}",
                    "size": size,
                    "field_type": field_type,
                    "access_count": total_access,
                    "top_access": top_access,
                    "suggested_name": suggested,
                    "read_count": offset_reads[offset],
                    "write_count": offset_writes[offset],
                })

        ifc.dispose()

        print(f"\n[total] class methods: {total_methods}, impl functions: {total_impl}")
        print(f"[total] field access points: {len(all_results)}")

    # Write CSV
    fieldnames = [
        "struct_path", "class_name", "offset", "size", "field_type",
        "access_count", "top_access", "suggested_name",
        "read_count", "write_count",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_results)

    print(f"\n[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
