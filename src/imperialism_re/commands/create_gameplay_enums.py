#!/usr/bin/env python3
"""
Create/update gameplay enums from a JSON specification and optionally type tables.

JSON spec format:
{
  "enums": [
    {
      "category": "/imperialism",
      "name": "EExample",
      "size": 2,
      "values": [["EXAMPLE_A", 0], ["EXAMPLE_B", 1]]
    }
  ],
  "tables": [
    {
      "address": "0x00600000",
      "enum_path": "/imperialism/EExample",
      "count": 10,
      "label": "g_aExample"
    }
  ]
}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import require_project_category_path, resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.ghidra_session import open_program


def _parse_int(value) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec-json", required=True, help="Path to enum/table specification JSON")
    ap.add_argument(
        "--apply-tables",
        action="store_true",
        help="Apply enum array data types for table entries in spec",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    spec_path = Path(args.spec_json)
    if not spec_path.is_absolute():
        spec_path = root / spec_path
    if not spec_path.exists():
        print(f"[error] missing spec json: {spec_path}")
        return 1

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    enum_specs = spec.get("enums") or []
    table_specs = spec.get("tables") or []
    if not enum_specs:
        print(f"[error] spec has no enums: {spec_path}")
        return 1

    with open_program(root) as program:
        from ghidra.program.model.data import (
            ArrayDataType,
            CategoryPath,
            DataTypeConflictHandler,
            EnumDataType,
        )
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        tx = program.startTransaction("Create gameplay enums")
        try:
            for item in enum_specs:
                category = require_project_category_path(str(item["category"]))
                name = str(item["name"])
                size = _parse_int(item["size"])
                values = item.get("values") or []
                e = EnumDataType(CategoryPath(category), name, size)
                for pair in values:
                    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                        raise ValueError(f"invalid enum value pair for {name}: {pair!r}")
                    member_name = str(pair[0])
                    member_value = _parse_int(pair[1])
                    e.add(member_name, member_value)
                dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
                print(f"[enum] {category}/{name} size={size} values={len(values)}")
        finally:
            program.endTransaction(tx, True)

        if args.apply_tables and table_specs:
            tx2 = program.startTransaction("Apply gameplay enum tables")
            try:
                for item in table_specs:
                    addr_i = _parse_int(item["address"])
                    enum_path = str(item["enum_path"])
                    count = _parse_int(item["count"])
                    label = str(item.get("label") or "")
                    addr = af.getAddress(f"0x{addr_i:08x}")
                    enum_dt = resolve_datatype_by_path_or_legacy_aliases(dtm, enum_path)
                    if enum_dt is None:
                        print(f"[warn] missing enum {enum_path}")
                        continue
                    arr = ArrayDataType(enum_dt, count, enum_dt.getLength())
                    end = addr.add(arr.getLength() - 1)
                    listing.clearCodeUnits(addr, end, False)
                    listing.createData(addr, arr)
                    if label:
                        syms = list(st.getSymbols(addr))
                        if not any(s.getName() == label for s in syms):
                            sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                            sym.setPrimary()
                    print(f"[table] {label or '<no-label>'} 0x{addr_i:08x} dtype={arr.getName()}")
            finally:
                program.endTransaction(tx2, True)

        program.save("create gameplay enums", None)
        print("[done]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
