#!/usr/bin/env python3
"""
Mine struct field access patterns from decompiled class methods.

For each class, decompiles all namespace methods **and their thunk/wrapper
targets** (Global-namespace implementation functions) and extracts
``this + offset`` access patterns.  Generates a CSV suitable for
``rename_struct_fields``.

Output CSV columns:
  struct_path, class_name, offset, size, field_type, access_count, top_access, suggested_name

Usage:
  uv run impk mine_struct_field_access \
    --classes TradeControl TGreatPower TGameWindow \
    --out-csv tmp_decomp/field_access_mine.csv

  uv run impk mine_struct_field_access \
    --top-n 20 \
    --out-csv tmp_decomp/field_access_mine.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


def _decompile(ifc, func) -> str:
    res = ifc.decompileFunction(func, 20, None)
    if not res or not res.decompileCompleted():
        return ""
    dc = res.getDecompiledFunction()
    if dc is None:
        return ""
    return str(dc.getC())


# Patterns to detect struct field access in decompiled C code:
#   *(int *)(this + 0x14)         → 4-byte int at offset 0x14
#   *(short *)(this + 0x08)       → 2-byte short at offset 0x08
#   *(byte *)(this + 0x0c)        → 1-byte at offset 0x0c
#   this->field14                 → named field (skip)
#   this + 0x18                   → pointer into struct at offset 0x18

# Cast type → field size
_CAST_SIZE = {
    "int": 4, "uint": 4, "undefined4": 4, "long": 4, "ulong": 4,
    "DWORD": 4, "UINT": 4, "BOOL": 4, "float": 4,
    "short": 2, "ushort": 2, "undefined2": 2, "WORD": 2,
    "byte": 1, "undefined1": 1, "char": 1, "BYTE": 1, "bool": 1,
    "longlong": 8, "undefined8": 8, "double": 8,
    "code": 4,  # function pointer
}

# Matches: *(type *)((int)this + 0xNN) or *(type *)(this + 0xNN)
_ACCESS_PATTERN = re.compile(
    r'\*\s*\((\w[\w\s]*?\*+)\s*\)'       # cast: *(type *)
    r'\s*\(\s*'
    r'(?:\(\w+\)\s*)?'                    # optional (int) cast
    r'(?:this|param_1|pThis|in_ECX)'      # this-like variable
    r'\s*\+\s*'
    r'(0x[0-9a-fA-F]+|\d+)'              # offset
    r'\s*\)',
)

# Matches bare pointer arithmetic: this + 0xNN (typed this)
_PTR_ARITH_PATTERN = re.compile(
    r'(?:\(\w+\)\s*)?'
    r'(?:this|param_1|pThis|in_ECX)'
    r'\s*\+\s*'
    r'(0x[0-9a-fA-F]+)',
)


def _extract_field_accesses(c_code: str) -> list[tuple[int, int, str]]:
    """Extract (offset, size, cast_type) tuples from decompiled C code."""
    results = []
    cast_offsets = set()

    for m in _ACCESS_PATTERN.finditer(c_code):
        cast_type = m.group(1).strip()
        offset_str = m.group(2)
        offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
        cast_offsets.add(offset)

        base = cast_type.rstrip("*").rstrip().split()[-1] if " " in cast_type else cast_type.rstrip("*").rstrip()
        ptr_depth = cast_type.count("*")

        if ptr_depth >= 2:
            size = 4
            access_type = "ptr*"
        elif ptr_depth == 1 and base.lower() in ("void", "undefined"):
            size = 4
            access_type = "void*"
        elif ptr_depth == 1:
            size = _CAST_SIZE.get(base, 4)
            access_type = base
        else:
            size = _CAST_SIZE.get(base, 4)
            access_type = base

        results.append((offset, size, access_type))

    # Also pick up bare pointer arithmetic: this + 0xNN (no cast, typed this)
    for m in _PTR_ARITH_PATTERN.finditer(c_code):
        offset_str = m.group(1)
        offset = int(offset_str, 16)
        if offset not in cast_offsets:
            results.append((offset, 4, "void*"))

    return results


def _get_thunk_target(fn, fm):
    """If fn is a simple thunk (calls exactly 1 other function), return that target."""
    body = fn.getBody()
    if body is None:
        return None
    # A thunk is typically very small (< 20 bytes)
    size = body.getNumAddresses()
    if size > 40:
        return None

    # Check if it's registered as a thunk
    thunked = fn.getThunkedFunction(False)
    if thunked is not None:
        return thunked

    # Otherwise, check called functions
    called = set()
    refs = fn.getCalledFunctions(None)  # monitor=None
    if refs is not None:
        for callee in refs:
            called.add(callee)

    if len(called) == 1:
        return list(called)[0]
    return None


def _collect_impl_functions(cls_ns, fm, global_ns, max_depth=3):
    """
    For a class namespace, collect all methods AND their thunk/wrapper
    target chains (Global implementation functions).
    Returns dict mapping function → class_name.
    """
    to_decompile = set()
    visited = set()

    # Start with all class methods
    fit = fm.getFunctions(True)
    while fit.hasNext():
        fn = fit.next()
        if fn.getParentNamespace() == cls_ns:
            to_decompile.add(fn)

    # Follow thunk chains into Global namespace
    frontier = set(to_decompile)
    for _ in range(max_depth):
        next_frontier = set()
        for fn in frontier:
            if fn in visited:
                continue
            visited.add(fn)
            target = _get_thunk_target(fn, fm)
            if target is not None and target not in to_decompile:
                # Only follow into Global namespace (implementation functions)
                if target.getParentNamespace() == global_ns:
                    to_decompile.add(target)
                    next_frontier.add(target)
        frontier = next_frontier
        if not frontier:
            break

    return to_decompile


def main() -> int:
    ap = argparse.ArgumentParser()
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
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.data import Structure

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
        class_struct_paths = {}
        for cls_name in sorted(target_classes):
            for cat_prefix in ["/imperialism/classes/", "/", "/imperialism/types/"]:
                dt = dtm.getDataType(f"{cat_prefix}{cls_name}")
                if dt is not None and isinstance(dt, Structure):
                    class_struct_paths[cls_name] = (f"{cat_prefix}{cls_name}", dt)
                    break
            if cls_name not in class_struct_paths:
                print(f"[skip] no struct found for {cls_name}")

        # Set up decompiler
        ifc = DecompInterface()
        ifc.openProgram(program)

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

            # Collect field access from all collected functions
            offset_accesses = defaultdict(Counter)
            method_count = len(class_methods)
            impl_count = len(impl_fns)

            decompiled = 0
            for fn in all_fns:
                if args.max_methods and decompiled >= args.max_methods:
                    break

                decompiled += 1
                c_code = _decompile(ifc, fn)
                if not c_code:
                    continue

                accesses = _extract_field_accesses(c_code)
                if args.verbose and accesses:
                    ns_tag = "impl" if fn.getParentNamespace() == global_ns else "cls"
                    print(f"  [{ns_tag}] {fn.getName()}: {len(accesses)} accesses")

                for offset, size, access_type in accesses:
                    if offset >= 0:
                        offset_accesses[offset][f"{access_type}:{size}"] += 1

            total_methods += method_count
            total_impl += impl_count
            print(f"[class] {cls_name}: {method_count} methods + {impl_count} impl fns, {len(offset_accesses)} offsets")

            # Generate field suggestions for unnamed offsets
            for offset in sorted(offset_accesses.keys()):
                if offset in existing_fields:
                    continue

                access_counts = offset_accesses[offset]
                total_access = sum(access_counts.values())
                top_access, top_count = access_counts.most_common(1)[0]
                access_type, size = top_access.split(":")
                size = int(size)

                if "*" in access_type or "void" in access_type.lower():
                    suggested = f"pField{offset:02x}"
                    field_type = "void*"
                elif access_type in ("int", "uint", "undefined4", "long", "ulong", "DWORD", "UINT"):
                    suggested = f"field{offset:02x}"
                    field_type = "int"
                elif access_type in ("short", "ushort", "undefined2", "WORD"):
                    suggested = f"field{offset:02x}"
                    field_type = "short"
                elif access_type in ("byte", "bool", "char", "undefined1", "BYTE"):
                    suggested = f"field{offset:02x}"
                    field_type = "byte"
                elif access_type in ("float",):
                    suggested = f"fField{offset:02x}"
                    field_type = "float"
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
                })

        ifc.dispose()

        print(f"\n[total] class methods: {total_methods}, impl functions: {total_impl}")
        print(f"[total] field access points: {len(all_results)}")

        # Write CSV
        fieldnames = ["struct_path", "class_name", "offset", "size", "field_type",
                       "access_count", "top_access", "suggested_name"]
        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(all_results)

    print(f"\n[saved] {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
