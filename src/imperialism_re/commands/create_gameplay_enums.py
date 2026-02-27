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
from collections import OrderedDict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import (
    require_project_category_path,
    resolve_datatype_by_path_or_legacy_aliases,
)
from imperialism_re.core.ghidra_session import open_program


def _parse_int(value) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _resolve_spec_paths(root: Path, raw_paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in raw_paths:
        p = Path(raw)
        if not p.is_absolute():
            p = root / p
        if not p.exists():
            raise FileNotFoundError(f"missing spec json: {p}")
        out.append(p)
    return out


def _merge_specs(spec_paths: list[Path]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    merged_enums: OrderedDict[tuple[str, str], dict[str, object]] = OrderedDict()
    merged_tables: OrderedDict[tuple[int, str, int, str], dict[str, object]] = OrderedDict()

    for spec_path in spec_paths:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        enum_specs = spec.get("enums") or []
        table_specs = spec.get("tables") or []

        for item in enum_specs:
            category = require_project_category_path(str(item["category"]))
            name = str(item["name"])
            size = _parse_int(item["size"])
            key = (category, name)
            existing = merged_enums.get(key)
            if existing is None:
                existing = {
                    "category": category,
                    "name": name,
                    "size": size,
                    "members": OrderedDict(),
                }
                merged_enums[key] = existing
            elif int(existing["size"]) != size:
                print(
                    f"[warn] enum size mismatch for {category}/{name}: "
                    f"existing={existing['size']} incoming={size} (keeping existing)"
                )

            members = existing["members"]
            for pair in item.get("values") or []:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    raise ValueError(f"invalid enum value pair for {name}: {pair!r}")
                member_name = str(pair[0])
                member_value = _parse_int(pair[1])
                if member_value in members:
                    if members[member_value] != member_name:
                        print(
                            f"[warn] enum member conflict {category}/{name} "
                            f"value={member_value} existing={members[member_value]} "
                            f"incoming={member_name} (keeping existing)"
                        )
                    continue
                members[member_value] = member_name

        for item in table_specs:
            try:
                addr_i = _parse_int(item["address"])
                enum_path = str(item["enum_path"])
                count = _parse_int(item["count"])
                label = str(item.get("label") or "")
            except Exception:
                continue
            if count <= 0:
                continue
            merged_tables[(addr_i, enum_path, count, label)] = {
                "address": addr_i,
                "enum_path": enum_path,
                "count": count,
                "label": label,
            }

    enum_out: list[dict[str, object]] = []
    for category, name in sorted(merged_enums.keys(), key=lambda x: (x[0], x[1])):
        entry = merged_enums[(category, name)]
        members = entry["members"]
        ordered_values = [[members[v], v] for v in sorted(members.keys())]
        enum_out.append(
            {
                "category": category,
                "name": name,
                "size": int(entry["size"]),
                "values": ordered_values,
            }
        )

    table_out = [merged_tables[k] for k in sorted(merged_tables.keys(), key=lambda x: (x[0], x[1], x[2], x[3]))]
    return enum_out, table_out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--spec-json",
        action="append",
        required=True,
        help="Path to enum/table specification JSON; pass multiple times to merge specs",
    )
    ap.add_argument(
        "--apply-tables",
        action="store_true",
        help="Apply enum array data types for table entries in spec",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    try:
        spec_paths = _resolve_spec_paths(root, list(args.spec_json))
    except FileNotFoundError as ex:
        print(f"[error] {ex}")
        return 1

    enum_specs, table_specs = _merge_specs(spec_paths)
    if not enum_specs:
        print(f"[error] specs have no enums: {', '.join(str(p) for p in spec_paths)}")
        return 1
    print(
        f"[plan] specs={len(spec_paths)} enums={len(enum_specs)} tables={len(table_specs)} "
        f"apply_tables={int(args.apply_tables)}"
    )

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
