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
    alias_datatype_paths,
    require_project_category_path,
    resolve_datatype_by_path_or_legacy_aliases,
)
from imperialism_re.core.ghidra_session import open_program


def _parse_int(value) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _enum_members_map(enum_dt) -> OrderedDict[int, str]:
    out: OrderedDict[int, str] = OrderedDict()
    try:
        names = list(enum_dt.getNames())
    except Exception:
        names = []
    for name in names:
        try:
            value = int(enum_dt.getValue(name))
        except Exception:
            continue
        if value in out:
            continue
        out[value] = str(name)
    return out


def _existing_enum_variants(dtm, enum_path: str) -> list[object]:
    out = []
    seen = set()
    for path in alias_datatype_paths(enum_path):
        dt = dtm.getDataType(path)
        if dt is None:
            continue
        try:
            key = str(dt.getPathName())
        except Exception:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(dt)
    return out


def _merge_enum_members(
    existing_enums: list[object],
    incoming_values: list[list[object] | tuple[object, object]],
    enum_path: str,
) -> list[tuple[str, int]]:
    merged: OrderedDict[int, str] = OrderedDict()
    for existing_enum in existing_enums:
        for value, name in _enum_members_map(existing_enum).items():
            if int(value) in merged:
                continue
            merged[int(value)] = str(name)

    for pair in incoming_values:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError(f"invalid enum value pair for {enum_path}: {pair!r}")
        in_name = str(pair[0])
        in_value = _parse_int(pair[1])
        if in_value in merged:
            if merged[in_value] != in_name:
                print(
                    f"[warn] enum value-name conflict {enum_path} value={in_value}: "
                    f"existing={merged[in_value]} incoming={in_name} (keeping existing)"
                )
            continue
        merged[in_value] = in_name

    return [(merged[v], v) for v in sorted(merged.keys())]


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
                incoming_size = _parse_int(item["size"])
                size = incoming_size
                values = item.get("values") or []
                enum_path = f"{category}/{name}"
                existing_enums = _existing_enum_variants(dtm, enum_path)
                existing_sizes = []
                for ex in existing_enums:
                    try:
                        ex_len = int(ex.getLength())
                    except Exception:
                        ex_len = 0
                    if ex_len > 0:
                        existing_sizes.append(ex_len)
                if existing_sizes:
                    chosen_size = min(existing_sizes)
                    if chosen_size != incoming_size or len(set(existing_sizes)) > 1:
                        print(
                            f"[warn] enum size differs for {enum_path}: "
                            f"existing_sizes={sorted(set(existing_sizes))} incoming={incoming_size} "
                            f"(keeping {chosen_size})"
                        )
                    size = chosen_size
                merged_values = _merge_enum_members(existing_enums, values, enum_path)
                e = EnumDataType(CategoryPath(category), name, size)
                for member_name, member_value in merged_values:
                    e.add(member_name, member_value)
                dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
                print(f"[enum] {category}/{name} size={size} values={len(merged_values)}")
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
