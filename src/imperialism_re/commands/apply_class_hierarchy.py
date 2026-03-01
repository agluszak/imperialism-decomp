#!/usr/bin/env python3
"""
Embed parent class structs at offset 0 of derived class structs in Ghidra.

Reads ``class_hierarchy_edges_ranked.csv`` (produced by ``reconstruct_class_hierarchy``),
picks the single best parent per class, topologically sorts the edges so multi-level
chains are processed base-first, and replaces the ``void* pVtable`` slot at offset 0
with the actual parent struct.

Usage:
  uv run impk apply_class_hierarchy
  uv run impk apply_class_hierarchy --apply
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict, deque
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import project_category_path
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_int_default


def _topo_sort(edges: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Topological sort of (base, derived) edges so bases are processed first."""
    children: dict[str, list[tuple[str, str]]] = defaultdict(list)
    parent_of: dict[str, str] = {}
    all_nodes: set[str] = set()
    for base, derived in edges:
        children[base].append((base, derived))
        parent_of[derived] = base
        all_nodes.add(base)
        all_nodes.add(derived)

    # In-degree: how many ancestors must be processed first for each base node
    # We want to process edges whose base has no parent before edges whose base
    # has a parent (i.e. the base itself is a derived class of something).
    in_degree: dict[str, int] = defaultdict(int)
    for base, derived in edges:
        # The edge (base, derived) needs 'base' to already have been embedded
        # into its own parent (if any).  So count base's incoming edges.
        pass  # computed below

    # Build a graph over base nodes: if base B is itself a derived class of A,
    # then edges from B depend on edges from A being done first.
    bases_set = {base for base, _ in edges}
    derived_set = {derived for _, derived in edges}
    # Nodes that are both base and derived form chains.
    for base, derived in edges:
        if base in derived_set:
            in_degree[base] += 0  # ensure present
        in_degree.setdefault(base, 0)

    # Re-approach: sort edges so that for any chain A→B→C, the edge (A,B) comes
    # before (B,C).  An edge (base, derived) depends on all edges where derived == base.
    edge_in_degree: dict[tuple[str, str], int] = {}
    edge_dependents: dict[str, list[tuple[str, str]]] = defaultdict(list)  # base_name → edges that need it done

    for e in edges:
        base, derived = e
        # This edge depends on any edge that has base as its derived
        edge_in_degree[e] = 0

    for e in edges:
        base, derived = e
        # Any edge whose derived == our base must come before us
        # We'll count those after building the lookup
        pass

    # edges_by_derived[X] = edges where derived == X
    edges_by_derived: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for e in edges:
        edges_by_derived[e[1]].append(e)

    for e in edges:
        base, derived = e
        # predecessors: edges whose derived == base (they must embed base first)
        preds = edges_by_derived.get(base, [])
        edge_in_degree[e] = len(preds)
        for pred in preds:
            edge_dependents.setdefault(pred, []).append(e)

    # Kahn's algorithm on edges
    queue: deque[tuple[str, str]] = deque()
    for e, deg in edge_in_degree.items():
        if deg == 0:
            queue.append(e)

    result: list[tuple[str, str]] = []
    while queue:
        e = queue.popleft()
        result.append(e)
        for dep in edge_dependents.get(e, []):
            edge_in_degree[dep] -= 1
            if edge_in_degree[dep] == 0:
                queue.append(dep)

    # If there are cycles, append remaining edges (shouldn't happen with real data)
    remaining = [e for e in edges if e not in set(result)]
    result.extend(remaining)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--csv",
        default="tmp_decomp/class_hierarchy_edges_ranked.csv",
        help="Ranked hierarchy CSV (default: tmp_decomp/class_hierarchy_edges_ranked.csv)",
    )
    ap.add_argument("--min-high-support", type=int, default=1, help="Min high_support to accept (default 1)")
    ap.add_argument("--min-total-support", type=int, default=3, help="Min total_support to accept (default 3)")
    ap.add_argument("--apply", action="store_true", help="Write changes (dry-run by default)")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = root / csv_path
    if not csv_path.exists():
        print(f"[error] missing csv: {csv_path}")
        return 1

    # --- Parse CSV and filter ---
    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    candidates: dict[str, list[dict]] = defaultdict(list)  # derived → [rows]
    for r in rows:
        base = (r.get("base_class") or "").strip()
        derived = (r.get("derived_class") or "").strip()
        if not base or not derived:
            continue
        high = int(r.get("high_support", 0))
        total = int(r.get("total_support", 0))
        if high >= args.min_high_support or total >= args.min_total_support:
            candidates[derived].append(r)

    # --- Single parent per class: pick highest (high_support, total_support) ---
    edges: list[tuple[str, str]] = []
    chosen: dict[str, str] = {}  # derived → base
    for derived, cands in candidates.items():
        best = max(cands, key=lambda c: (int(c.get("high_support", 0)), int(c.get("total_support", 0))))
        base = best["base_class"].strip()
        edges.append((base, derived))
        chosen[derived] = base

    # --- Topological sort ---
    edges = _topo_sort(edges)

    category = project_category_path("classes")
    print(f"[plan] edges={len(edges)} min_high={args.min_high_support} min_total={args.min_total_support} apply={args.apply}")
    for base, derived in edges:
        print(f"  {base} → {derived}")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    # --- Apply in Ghidra ---
    with open_program(root) as program:
        from ghidra.program.model.data import (
            DataTypeConflictHandler,
            Pointer,
            Structure,
        )

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Apply class hierarchy: embed parent structs")
        embedded = 0
        grown = 0
        skipped_already = 0
        skipped_missing = 0
        failed = 0

        try:
            for base_name, derived_name in edges:
                base_path = f"{category}/{base_name}"
                derived_path = f"{category}/{derived_name}"

                base_dt = dtm.getDataType(base_path)
                derived_dt = dtm.getDataType(derived_path)

                if base_dt is None:
                    print(f"[skip] base struct missing: {base_path}")
                    skipped_missing += 1
                    continue
                if derived_dt is None:
                    print(f"[skip] derived struct missing: {derived_path}")
                    skipped_missing += 1
                    continue
                if not isinstance(base_dt, Structure) or not isinstance(derived_dt, Structure):
                    print(f"[skip] not structs: {base_path} or {derived_path}")
                    skipped_missing += 1
                    continue

                # Check offset 0 of derived — skip if already a struct (prior embedding)
                comp0 = derived_dt.getComponentAt(0)
                if comp0 is not None and isinstance(comp0.getDataType(), Structure):
                    print(f"[skip] {derived_name}: offset 0 already struct ({comp0.getDataType().getName()})")
                    skipped_already += 1
                    continue

                try:
                    st = derived_dt.copy(dtm)
                    base_len = base_dt.getLength()
                    current_len = st.getLength()

                    # Grow if base is larger than current derived
                    if base_len > current_len:
                        st.growStructure(base_len - current_len)
                        grown += 1
                        print(f"[grow] {derived_name}: 0x{current_len:x} → 0x{base_len:x}")

                    # Clear all defined components in [0, base_len) so replaceAtOffset
                    # doesn't collide with existing typed fields.
                    for off in range(base_len):
                        c = st.getComponentAt(off)
                        if c is not None and c.getOffset() == off:
                            st.clearAtOffset(off)

                    st.replaceAtOffset(0, base_dt, base_len, "base", f"parent class: {base_name}")
                    st.setDescription(f"Derived from {base_name}")
                    dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
                    embedded += 1
                except Exception as ex:
                    print(f"[fail] {derived_name}: {ex}")
                    failed += 1

        finally:
            program.endTransaction(tx, True)

        program.save("apply class hierarchy", None)
        print(
            f"\n[done] embedded={embedded} grown={grown} "
            f"skip_already={skipped_already} skip_missing={skipped_missing} "
            f"failed={failed}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
