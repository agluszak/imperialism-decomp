#!/usr/bin/env python3
"""
Apply a manually curated class struct layout.

This is intended for cases where automated offset mining includes false positives
(e.g., vtable slot offsets parsed as instance fields). It rebuilds a class struct
with a conservative `pVtable` at offset 0 and caller-specified fields.

Usage:
  .venv/bin/python new_scripts/apply_manual_struct_fields.py \
    --class TGameWindow \
    --size 0xb0 \
    --field 0x28:byte:bField_28 \
    --field 0xa2:ushort:wField_A2 \
    --field 0xa4:uint:dwField_A4 \
    --field 0xa8:uint:dwField_A8 \
    --field 0xac:uint:dwField_AC \
    --apply
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_int(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def parse_field(field_arg: str):
    # <offset>:<type>:<name>
    parts = field_arg.split(":")
    if len(parts) != 3:
        raise ValueError(f"invalid --field format: {field_arg}")
    off = parse_int(parts[0])
    typ = parts[1].strip().lower()
    name = parts[2].strip()
    if not name:
        raise ValueError(f"invalid field name in: {field_arg}")
    return off, typ, name


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="class_name", required=True, help="Class struct name")
    ap.add_argument("--size", required=True, help="Struct size (hex or decimal)")
    ap.add_argument("--field", action="append", default=[], help="Field spec offset:type:name")
    ap.add_argument(
        "--category", default="/imperialism/classes", help="Datatype category (default /imperialism/classes)"
    )
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    class_name = args.class_name
    struct_size = parse_int(args.size)
    fields = [parse_field(x) for x in args.field]
    fields.sort(key=lambda x: x[0])

    print(f"[plan] class={class_name} size=0x{struct_size:x} fields={len(fields)} apply={args.apply}")
    for off, typ, name in fields:
        print(f"  - 0x{off:x} {typ} {name}")

    if not args.apply:
        return 0

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import (
            ByteDataType,
            CategoryPath,
            DataTypeConflictHandler,
            PointerDataType,
            ShortDataType,
            StructureDataType,
            UnsignedIntegerDataType,
            UnsignedShortDataType,
            VoidDataType,
        )

        dtm = program.getDataTypeManager()
        cat = CategoryPath(args.category)

        def dtype_for(name: str):
            if name in ("byte", "uchar", "u8"):
                return ByteDataType.dataType
            if name in ("short", "s16"):
                return ShortDataType.dataType
            if name in ("ushort", "word", "u16"):
                return UnsignedShortDataType.dataType
            if name in ("uint", "dword", "u32", "int"):
                return UnsignedIntegerDataType.dataType
            if name in ("ptr", "void*", "pointer"):
                return PointerDataType(VoidDataType.dataType)
            raise ValueError(f"unsupported field type: {name}")

        p_void = PointerDataType(VoidDataType.dataType)

        st = StructureDataType(cat, class_name, max(struct_size, 4))
        st.replaceAtOffset(0, p_void, 4, "pVtable", "manual: vtable pointer")
        for off, typ, name in fields:
            dt = dtype_for(typ)
            st.replaceAtOffset(off, dt, dt.getLength(), name, "manual layout")

        tx = program.startTransaction(f"Apply manual struct {class_name}")
        try:
            dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)
        program.save(f"apply manual struct {class_name}", None)
        print("[done] applied")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
