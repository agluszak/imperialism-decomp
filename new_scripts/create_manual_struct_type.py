#!/usr/bin/env python3
"""
Create/update a manual structure datatype.

Unlike apply_manual_struct_fields.py, this tool does not force a vtable field unless
--add-vtable is requested.

Usage:
  .venv/bin/python new_scripts/create_manual_struct_type.py \
    --name PanelEventPayload \
    --size 0x24 \
    --field 0x1c:uint:eventCode1c \
    --field 0x20:ptr:pOwner20 \
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


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def parse_field(field_arg: str):
    parts = field_arg.split(":")
    if len(parts) != 3:
        raise ValueError(f"invalid --field format: {field_arg}")
    off = parse_int(parts[0])
    typ = parts[1].strip().lower()
    name = parts[2].strip()
    if not name:
        raise ValueError(f"invalid field name in: {field_arg}")
    return off, typ, name


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="Datatype name")
    ap.add_argument("--size", required=True, help="Struct size (hex or decimal)")
    ap.add_argument("--field", action="append", default=[], help="offset:type:name")
    ap.add_argument("--category", default="/imperialism/types", help="Datatype category path")
    ap.add_argument("--add-vtable", action="store_true", help="Add pVtable at offset 0")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    name = args.name.strip()
    size = parse_int(args.size)
    fields = [parse_field(x) for x in args.field]
    fields.sort(key=lambda x: x[0])

    print(
        f"[plan] name={name} size=0x{size:x} category={args.category} "
        f"add_vtable={int(args.add_vtable)} fields={len(fields)} apply={args.apply}"
    )
    for off, typ, fname in fields:
        print(f"  - 0x{off:x} {typ} {fname}")

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

        def dtype_for(kind: str):
            if kind in ("byte", "u8", "char"):
                return ByteDataType.dataType
            if kind in ("short", "s16"):
                return ShortDataType.dataType
            if kind in ("ushort", "u16", "word"):
                return UnsignedShortDataType.dataType
            if kind in ("int", "uint", "u32", "dword"):
                return UnsignedIntegerDataType.dataType
            if kind in ("ptr", "void*", "pointer"):
                return PointerDataType(VoidDataType.dataType)
            raise ValueError(f"unsupported field type: {kind}")

        dtm = program.getDataTypeManager()
        cat = CategoryPath(args.category)
        p_void = PointerDataType(VoidDataType.dataType)

        st = StructureDataType(cat, name, max(1, size))
        if args.add_vtable:
            st.replaceAtOffset(0, p_void, 4, "pVtable", "manual")
        for off, typ, fname in fields:
            dt = dtype_for(typ)
            st.replaceAtOffset(off, dt, dt.getLength(), fname, "manual")

        tx = program.startTransaction(f"Create manual struct {name}")
        try:
            dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)
        program.save(f"create manual struct {name}", None)
        print("[done] applied")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
