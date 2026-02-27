#!/usr/bin/env python3
"""
Rename (and optionally retype) existing structure fields by exact offset.

Usage:
  uv run impk rename_struct_fields \
    --path /TradeControl \
    --path /imperialism/classes/TradeControl \
    --rename 0x04:cityDialogFlag4 \
    --rename 0x08:controlActiveFlag8 \
    --rename 0x0c:dialogValueDwordC \
    --rename 0x10:dialogValueDword10 \
    --rename 0x18:pUiOwner18 \
    --apply

  # Optional type override format:
  --rename 0x04:byte:cityDialogFlag4
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_int

def parse_rename(spec: str):
    # offset:name OR offset:type:name
    parts = spec.split(":")
    if len(parts) == 2:
        off = parse_int(parts[0])
        typ = None
        name = parts[1].strip()
    elif len(parts) == 3:
        off = parse_int(parts[0])
        typ = parts[1].strip().lower()
        name = parts[2].strip()
    else:
        raise ValueError(f"invalid --rename spec: {spec}")
    if not name:
        raise ValueError(f"empty field name in --rename spec: {spec}")
    return off, typ, name

def dtype_for(kind: str):
    from ghidra.program.model.data import (
        ByteDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

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
    raise ValueError(f"unsupported type override: {kind}")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", action="append", default=[], help="Datatype path, e.g. /TradeControl")
    ap.add_argument("--rename", action="append", default=[], help="offset:name or offset:type:name")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    if not args.path:
        print("no --path provided")
        return 1
    if not args.rename:
        print("no --rename provided")
        return 1

    renames = [parse_rename(x) for x in args.rename]
    renames.sort(key=lambda x: x[0])

    print(f"[plan] paths={len(args.path)} renames={len(renames)} apply={args.apply}")
    for path in args.path:
        print(f"  [path] {path}")
    for off, typ, name in renames:
        if typ:
            print(f"  - 0x{off:x} -> {name} (type {typ})")
        else:
            print(f"  - 0x{off:x} -> {name}")

    if not args.apply:
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.data import DataTypeConflictHandler, Structure

        dtm = program.getDataTypeManager()
        tx = program.startTransaction("Rename struct fields")
        ok = 0
        fail = 0
        try:
            for path in args.path:
                dt = dtm.getDataType(path)
                if dt is None:
                    print(f"[skip] missing datatype: {path}")
                    fail += len(renames)
                    continue
                if not isinstance(dt, Structure):
                    print(f"[skip] not a structure: {path}")
                    fail += len(renames)
                    continue

                st = dt.copy(dtm)
                print(f"[struct] {path} size=0x{st.getLength():x}")
                for off, typ, new_name in renames:
                    comp = st.getComponentContaining(off)
                    if comp is None:
                        print(f"  [miss] +0x{off:x} no component")
                        fail += 1
                        continue
                    if comp.getOffset() != off:
                        print(
                            f"  [miss] +0x{off:x} inside component at +0x{comp.getOffset():x}; skip exact-rename"
                        )
                        fail += 1
                        continue
                    old_name = comp.getFieldName() or "<anon>"
                    old_dt = comp.getDataType()
                    old_comment = comp.getComment()
                    use_dt = old_dt if typ is None else dtype_for(typ)
                    use_len = use_dt.getLength()
                    st.replaceAtOffset(off, use_dt, use_len, new_name, old_comment)
                    print(
                        f"  [ok] +0x{off:x} {old_name}:{old_dt.getName()} -> {new_name}:{use_dt.getName()}"
                    )
                    ok += 1

                dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)

        program.save("rename struct fields", None)
        print(f"[done] ok={ok} fail={fail}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

