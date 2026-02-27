#!/usr/bin/env python3
"""
Move class-associated datatypes from root ``/`` to ``/imperialism/classes/``.

Only moves datatypes whose names match known class namespaces in the symbol
table, avoiding Ghidra built-in types.

Usage:
  uv run impk move_class_datatypes_to_canonical --apply
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program


CANONICAL_CLASS_ROOT = "/imperialism/classes"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    with open_program(root) as program:
        from ghidra.program.model.data import CategoryPath

        dtm = program.getDataTypeManager()
        st = program.getSymbolTable()

        # Collect all class namespace names
        class_names = set()
        it = st.getClassNamespaces()
        while it.hasNext():
            class_names.add(it.next().getName())

        print(f"[info] {len(class_names)} class namespaces found")

        # Find root-level datatypes that match class names
        plans = []  # (datatype, dest_category)
        it = dtm.getAllDataTypes()
        while it.hasNext():
            dt = it.next()
            cat_path = str(dt.getCategoryPath().getPath())
            name = str(dt.getName())

            # Only consider types at root "/" (not subcategories)
            if cat_path != "/":
                continue

            # Only move if name matches a known class
            if name not in class_names:
                continue

            # Check if destination already exists
            dest_full = f"{CANONICAL_CLASS_ROOT}/{name}"
            existing = dtm.getDataType(dest_full)
            if existing is not None:
                # Collision — check which is richer
                src_size = dt.getLength() if hasattr(dt, "getLength") else 0
                dst_size = existing.getLength() if hasattr(existing, "getLength") else 0
                if src_size > dst_size:
                    plans.append((dt, CANONICAL_CLASS_ROOT, "collision-src-richer", existing))
                else:
                    plans.append((dt, CANONICAL_CLASS_ROOT, "collision-dst-richer", existing))
                continue

            plans.append((dt, CANONICAL_CLASS_ROOT, "move", None))

        moves = [(d, c, a, e) for d, c, a, e in plans if a == "move"]
        src_richer = [(d, c, a, e) for d, c, a, e in plans if a == "collision-src-richer"]
        dst_richer = [(d, c, a, e) for d, c, a, e in plans if a == "collision-dst-richer"]

        print(f"[plan] {len(moves)} moves, {len(src_richer)} collisions (src richer), {len(dst_richer)} collisions (dst richer)")

        for dt, _, action, _ in plans[:30]:
            print(f"  [{action}] /{dt.getName()} → {CANONICAL_CLASS_ROOT}/{dt.getName()}")
        if len(plans) > 30:
            print(f"  ... ({len(plans) - 30} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Move class datatypes to canonical root")
        ok = 0
        fail = 0
        try:
            # Simple moves (no collision)
            for dt, cat, action, _ in moves:
                try:
                    dt.setCategoryPath(CategoryPath(cat))
                    ok += 1
                except Exception as e:
                    print(f"  [err] {dt.getName()}: {e}")
                    fail += 1

            # Collisions where source is richer — replace destination with source
            for dt, cat, action, existing in src_richer:
                try:
                    dtm.replaceDataType(existing, dt, True)
                    ok += 1
                except Exception as e:
                    print(f"  [err] {dt.getName()} collision replace: {e}")
                    fail += 1

            # Collisions where destination is richer — replace source refs with destination
            for dt, cat, action, existing in dst_richer:
                try:
                    dtm.replaceDataType(dt, existing, False)
                    ok += 1
                except Exception as e:
                    print(f"  [err] {dt.getName()} collision repoint: {e}")
                    fail += 1

        finally:
            program.endTransaction(tx, True)

        program.save("move class datatypes to canonical root", None)
        print(f"[done] ok={ok} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
