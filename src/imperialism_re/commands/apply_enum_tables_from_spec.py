#!/usr/bin/env python3
"""
Apply enum-array table typing from a gameplay enum spec JSON.

Uses the `tables` section from JSON in create_gameplay_enums format.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import resolve_datatype_by_path_or_legacy_aliases
from imperialism_re.core.ghidra_session import open_program


def _parse_int(value) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec-json", required=True)
    ap.add_argument("--apply", action="store_true", help="Write table datatypes")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    spec_json = Path(args.spec_json)
    if not spec_json.is_absolute():
        spec_json = root / spec_json
    if not spec_json.exists():
        print(f"[error] missing spec json: {spec_json}")
        return 1

    spec = json.loads(spec_json.read_text(encoding="utf-8"))
    tables = spec.get("tables") or []
    if not tables:
        print(f"[done] no tables in spec: {spec_json}")
        return 0

    plan = []
    for item in tables:
        try:
            addr_i = _parse_int(item["address"])
            enum_path = str(item["enum_path"])
            count = _parse_int(item["count"])
            label = str(item.get("label") or "")
        except Exception:
            continue
        if count <= 0:
            continue
        plan.append((addr_i, enum_path, count, label))

    print(f"[plan] tables={len(plan)} apply={int(args.apply)}")
    for addr_i, enum_path, count, label in plan[:200]:
        print(
            f"  0x{addr_i:08x} enum={enum_path} count={count} label={label or '<none>'}"
        )
    if len(plan) > 200:
        print(f"... ({len(plan)-200} more)")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    with open_program(root) as program:
        from ghidra.program.model.data import ArrayDataType
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        tx = program.startTransaction("Apply enum tables from spec")
        ok = skip = fail = 0
        try:
            for addr_i, enum_path, count, label in plan:
                try:
                    enum_dt = resolve_datatype_by_path_or_legacy_aliases(dtm, enum_path)
                    if enum_dt is None:
                        fail += 1
                        print(f"[fail] 0x{addr_i:08x} missing enum {enum_path}")
                        continue

                    arr = ArrayDataType(enum_dt, count, enum_dt.getLength())
                    addr = af.getAddress(f"0x{addr_i:08x}")
                    end = addr.add(arr.getLength() - 1)
                    listing.clearCodeUnits(addr, end, False)
                    listing.createData(addr, arr)

                    if label:
                        syms = list(st.getSymbols(addr))
                        if not any(s.getName() == label for s in syms):
                            sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                            sym.setPrimary()
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{addr_i:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply enum tables from spec", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
