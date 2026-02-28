#!/usr/bin/env python3
"""
Run ``FillOutStructureCmd`` on class methods to auto-grow struct layouts.

For each target class, finds ``__thiscall`` methods whose param0 is already
typed as ``ClassName*`` (prerequisite: ``apply_class_this_param_types`` must
have run) and invokes Ghidra's ``FillOutStructureCmd`` to let the decompiler
fill in struct fields it can infer from usage patterns.

Classes are processed in topological order (base classes first) when a
hierarchy CSV is provided, so that parent struct changes propagate to
derived classes.

Dry-run by default — pass ``--apply`` to write changes.

Usage:
  uv run impk fill_out_structure_wave --classes TradeControl
  uv run impk fill_out_structure_wave --all-classes --hierarchy-csv tmp_decomp/class_hierarchy_edges_ranked.csv --apply
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict, deque
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.decompiler import create_configured_decompiler
from imperialism_re.core.ghidra_session import open_program


# ---------------------------------------------------------------------------
# Topological sort (same algorithm as apply_class_hierarchy)
# ---------------------------------------------------------------------------

def _topo_sort_classes(
    edges: list[tuple[str, str]],
    all_classes: list[str],
) -> list[str]:
    """Return *all_classes* sorted so that base classes come before derived.

    *edges* is a list of ``(base, derived)`` pairs.  Classes not mentioned
    in any edge keep their original relative order.
    """
    children: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = defaultdict(int)

    class_set = set(all_classes)
    for base, derived in edges:
        if base in class_set and derived in class_set:
            children[base].append(derived)
            in_degree[derived] += 1
            in_degree.setdefault(base, 0)

    # Kahn's algorithm
    queue: deque[str] = deque()
    for cls in all_classes:
        if in_degree.get(cls, 0) == 0:
            queue.append(cls)

    ordered: list[str] = []
    visited: set[str] = set()
    while queue:
        cls = queue.popleft()
        if cls in visited:
            continue
        visited.add(cls)
        ordered.append(cls)
        for child in children.get(cls, []):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    # Append any remaining (cycle participants or disconnected)
    for cls in all_classes:
        if cls not in visited:
            ordered.append(cls)

    return ordered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run FillOutStructureCmd on class methods to auto-grow struct layouts.",
    )
    ap.add_argument("--classes", nargs="*", default=[], help="Specific classes to process")
    ap.add_argument("--all-classes", action="store_true", help="Process all classes with existing structs")
    ap.add_argument(
        "--hierarchy-csv",
        default="",
        help="Ranked hierarchy CSV for topological ordering (optional)",
    )
    ap.add_argument("--apply", action="store_true", help="Write changes (dry-run by default)")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    # Parse hierarchy CSV if provided
    hierarchy_edges: list[tuple[str, str]] = []
    if args.hierarchy_csv:
        csv_path = Path(args.hierarchy_csv)
        if not csv_path.is_absolute():
            csv_path = root / csv_path
        if csv_path.exists():
            rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
            for r in rows:
                base = (r.get("base_class") or "").strip()
                derived = (r.get("derived_class") or "").strip()
                if base and derived:
                    hierarchy_edges.append((base, derived))
            print(f"[hierarchy] loaded {len(hierarchy_edges)} edges from {csv_path}")
        else:
            print(f"[warn] hierarchy CSV not found: {csv_path}")

    with open_program(root) as program:
        from ghidra.program.model.data import Structure
        from ghidra.util.task import TaskMonitor

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()
        stt = program.getSymbolTable()

        # Determine target classes
        target_classes: list[str] = []
        if args.all_classes:
            it_cls = stt.getClassNamespaces()
            while it_cls.hasNext():
                cls_name = it_cls.next().getName()
                dt = dtm.getDataType(f"/imperialism/classes/{cls_name}")
                if dt is not None and isinstance(dt, Structure):
                    target_classes.append(cls_name)
        else:
            target_classes = list(args.classes)

        if not target_classes:
            print("[error] no classes selected (use --classes or --all-classes)")
            return 1

        # Filter to classes with existing structs
        class_structs: dict[str, object] = {}
        for cls_name in target_classes:
            dt = dtm.getDataType(f"/imperialism/classes/{cls_name}")
            if dt is not None and isinstance(dt, Structure):
                class_structs[cls_name] = dt
            else:
                print(f"[skip] no struct at /imperialism/classes/{cls_name}")

        # Topological sort
        ordered = _topo_sort_classes(hierarchy_edges, sorted(class_structs.keys()))
        print(f"[plan] {len(ordered)} classes to process (apply={args.apply})")

        # Set up decompiler
        ifc = create_configured_decompiler(program)
        decomp_opts = ifc.getOptions()

        # Try to import FillOutStructureCmd — handle API variations
        try:
            from ghidra.app.decompiler.util import FillOutStructureCmd
            from ghidra.program.util import VariableLocation
            use_new_api = True
        except ImportError:
            use_new_api = False
            try:
                from ghidra.app.decompiler.util import FillOutStructureCmd
            except ImportError:
                print("[error] FillOutStructureCmd not available in this Ghidra version")
                ifc.dispose()
                return 1

        tx = None
        if args.apply:
            tx = program.startTransaction("FillOutStructure wave")

        total_methods_processed = 0
        total_fields_added = 0
        class_reports = []

        try:
            for cls_name in ordered:
                struct_dt = class_structs.get(cls_name)
                if struct_dt is None:
                    continue

                size_before = struct_dt.getLength()
                fields_before = struct_dt.getNumComponents()

                # Find class namespace
                cls_ns = None
                it_cls = stt.getClassNamespaces()
                while it_cls.hasNext():
                    ns = it_cls.next()
                    if ns.getName() == cls_name:
                        cls_ns = ns
                        break

                if cls_ns is None:
                    continue

                # Collect __thiscall methods where param0 is typed as ClassName*
                eligible_methods = []
                fit = fm.getFunctions(True)
                while fit.hasNext():
                    fn = fit.next()
                    if fn.getParentNamespace() != cls_ns:
                        continue
                    cc = fn.getCallingConventionName()
                    if cc != "__thiscall":
                        continue
                    params = fn.getParameters()
                    if not params or len(params) == 0:
                        continue
                    p0 = params[0]
                    p0_type = p0.getDataType()
                    if p0_type is None:
                        continue
                    type_name = p0_type.getDisplayName()
                    # Must be typed as ClassName* (not void*)
                    if cls_name in type_name and "*" in type_name:
                        eligible_methods.append((fn, p0))

                methods_ok = 0
                for fn, p0 in eligible_methods:
                    try:
                        if use_new_api:
                            loc = VariableLocation(program, p0, 0, 0)
                            cmd = FillOutStructureCmd(loc, decomp_opts)
                        else:
                            cmd = FillOutStructureCmd(program, p0, ifc)

                        if args.apply:
                            ok = cmd.applyTo(program, TaskMonitor.DUMMY)
                            if ok:
                                methods_ok += 1
                        else:
                            methods_ok += 1
                    except Exception as ex:
                        print(f"  [fail] {cls_name}::{fn.getName()}: {ex}")

                total_methods_processed += len(eligible_methods)

                # Re-fetch struct to check changes
                struct_dt_after = dtm.getDataType(f"/imperialism/classes/{cls_name}")
                size_after = struct_dt_after.getLength() if struct_dt_after else size_before
                fields_after = struct_dt_after.getNumComponents() if struct_dt_after else fields_before
                delta_fields = fields_after - fields_before

                if delta_fields > 0:
                    total_fields_added += delta_fields

                class_reports.append({
                    "class": cls_name,
                    "methods": len(eligible_methods),
                    "methods_ok": methods_ok,
                    "size_before": size_before,
                    "size_after": size_after,
                    "fields_before": fields_before,
                    "fields_after": fields_after,
                })

                tag = "apply" if args.apply else "dry"
                print(
                    f"[{tag}] {cls_name}: {methods_ok}/{len(eligible_methods)} methods, "
                    f"size 0x{size_before:x}→0x{size_after:x}, "
                    f"fields {fields_before}→{fields_after}"
                )

                # Flush decompiler cache after each class so subsequent classes
                # see updated base structs
                if args.apply:
                    try:
                        ifc.flushCache()
                    except Exception:
                        # If flushCache is unavailable, dispose and recreate
                        ifc.dispose()
                        ifc = create_configured_decompiler(program)
                        decomp_opts = ifc.getOptions()

        finally:
            if tx is not None:
                program.endTransaction(tx, True)

        ifc.dispose()

        if args.apply:
            program.save("FillOutStructure wave", None)

        print(
            f"\n[done] classes={len(class_reports)} methods={total_methods_processed} "
            f"fields_added={total_fields_added} apply={args.apply}"
        )

        if not args.apply:
            print("[dry-run] pass --apply to write changes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
