#!/usr/bin/env python3
"""
Apply mined struct field names from CSV produced by ``mine_struct_field_access``.

For each struct/offset row in the CSV, this command:
1. Grows the struct if needed (when the max mined offset exceeds the current size).
2. Renames/retypes the field at each offset.

Skips offsets that already have a non-anonymous field name.

Usage:
  uv run impk apply_mined_struct_fields \
    --csv tmp_decomp/field_mine_all_classes.csv \
    --apply
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_int


def _resolve_type(kind: str, dtm):
    from ghidra.program.model.data import (
        ByteDataType,
        FloatDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    MAP = {
        "byte": ByteDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "float": FloatDataType.dataType,
    }
    if kind in MAP:
        return MAP[kind]
    if kind in ("void*", "ptr", "pointer"):
        return PointerDataType(VoidDataType.dataType)
    # Fallback: undefined4
    return UnsignedIntegerDataType.dataType


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Input CSV from mine_struct_field_access")
    ap.add_argument("--min-access", type=int, default=2, help="Min access count to apply (default 2)")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv)
    root = resolve_project_root(args.project_root)
    if not csv_path.is_absolute():
        csv_path = root / csv_path

    # Parse CSV: group by struct_path
    struct_fields = defaultdict(list)  # struct_path → [(offset, size, field_type, name, access_count)]
    with csv_path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            offset = parse_int(row["offset"])
            size = int(row["size"])
            field_type = row["field_type"]
            name = row["suggested_name"]
            access_count = int(row["access_count"])
            struct_path = row["struct_path"]

            if access_count < args.min_access:
                continue

            struct_fields[struct_path].append((offset, size, field_type, name, access_count))

    # Sort each struct's fields by offset
    for path in struct_fields:
        struct_fields[path].sort(key=lambda x: x[0])

    total_planned = sum(len(v) for v in struct_fields.values())
    print(f"[plan] {len(struct_fields)} structs, {total_planned} fields (min-access >= {args.min_access})")

    for path, fields in sorted(struct_fields.items()):
        max_offset = max(off + sz for off, sz, _, _, _ in fields)
        print(f"  [{path}] {len(fields)} fields, max offset+size = 0x{max_offset:x}")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    with open_program(root) as program:
        from ghidra.program.model.data import DataTypeConflictHandler, Structure

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Apply mined struct fields")
        total_ok = 0
        total_skip = 0
        total_grow = 0
        total_fail = 0

        try:
            for struct_path, fields in sorted(struct_fields.items()):
                dt = dtm.getDataType(struct_path)
                if dt is None:
                    print(f"[skip] missing: {struct_path}")
                    total_fail += len(fields)
                    continue
                if not isinstance(dt, Structure):
                    print(f"[skip] not structure: {struct_path}")
                    total_fail += len(fields)
                    continue

                st = dt.copy(dtm)
                current_size = st.getLength()
                max_needed = max(off + sz for off, sz, _, _, _ in fields)

                # Grow struct if needed
                if max_needed > current_size:
                    st.growStructure(max_needed - current_size)
                    total_grow += 1
                    print(f"[grow] {struct_path}: 0x{current_size:x} → 0x{max_needed:x}")

                ok = 0
                skip = 0
                fail = 0

                for offset, size, field_type, name, access_count in fields:
                    comp = st.getComponentContaining(offset)
                    if comp is None:
                        fail += 1
                        continue

                    # Skip if already has a meaningful name
                    existing_name = comp.getFieldName()
                    if existing_name and not existing_name.startswith("field_0x"):
                        skip += 1
                        continue

                    # Skip if component doesn't start at our offset (we're inside another field)
                    if comp.getOffset() != offset:
                        # The component at this offset belongs to a larger field
                        # Only skip if the larger field is already named
                        parent_comp = st.getComponentAt(comp.getOffset())
                        if parent_comp and parent_comp.getFieldName():
                            skip += 1
                            continue

                    try:
                        use_dt = _resolve_type(field_type, dtm)
                        use_len = use_dt.getLength()
                        old_comment = comp.getComment()
                        st.replaceAtOffset(offset, use_dt, use_len, name, old_comment)
                        ok += 1
                    except Exception as e:
                        print(f"  [err] {struct_path} +0x{offset:x}: {e}")
                        fail += 1

                dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
                total_ok += ok
                total_skip += skip
                total_fail += fail

                if ok > 0:
                    print(f"  [{struct_path}] ok={ok} skip={skip} fail={fail}")

        finally:
            program.endTransaction(tx, True)

        program.save("apply mined struct fields", None)
        print(f"\n[done] applied={total_ok} skipped={total_skip} grown={total_grow} failed={total_fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
