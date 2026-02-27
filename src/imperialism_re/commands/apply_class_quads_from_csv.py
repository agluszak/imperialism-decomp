#!/usr/bin/env python3
"""
Apply class quad renames and class labels from CSV rows.

Expected CSV columns (minimum):
  type_name,getter,desc

Optional columns:
  create,ctor,dtor,tname_addr,vtbl_addr

Usage:
  uv run impk apply_class_quads_from_csv <csv_path> [--project-root <path>]
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_optional_hex

def fmt(value: int | None) -> str:
    if value is None:
        return ""
    return f"0x{value:08x}"

def extract_vtbl_from_ctor(ifc, func) -> int | None:
    if func is None:
        return None
    res = ifc.decompileFunction(func, 20, None)
    if not res.decompileCompleted():
        return None
    code = res.getDecompiledFunction().getC()
    hits = re.findall(r"PTR_LAB_00([0-9a-fA-F]{6})", code)
    if not hits:
        return None
    return int("00" + hits[-1], 16)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument("csv_path")
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    root = resolve_project_root(args.project_root)
    if not csv_path.exists():
        print(f"missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8")))
    if not rows:
        print("no rows in csv")
        return 0

    with open_program(root) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        mem = program.getMemory()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        ifc = DecompInterface()
        ifc.openProgram(program)

        tx = program.startTransaction("Apply class quads from CSV")
        fn_ok = fn_skip = fn_fail = 0
        ns_ok = ns_skip = ns_fail = 0
        lbl_ok = lbl_skip = lbl_fail = 0
        c_ok = 0
        try:
            for row in rows:
                t = row.get("type_name", "").strip()
                if not t:
                    continue

                create = parse_optional_hex(row.get("create"))
                getter = parse_optional_hex(row.get("getter"))
                ctor = parse_optional_hex(row.get("ctor"))
                dtor = parse_optional_hex(row.get("dtor"))
                desc = parse_optional_hex(row.get("desc"))
                tname_addr = parse_optional_hex(row.get("tname_addr"))
                vtbl_addr = parse_optional_hex(row.get("vtbl_addr"))

                if desc is None or getter is None:
                    print(f"[skip] {t}: missing desc/getter")
                    continue

                if tname_addr is None:
                    try:
                        tname_addr = mem.getInt(af.getAddress(fmt(desc))) & 0xFFFFFFFF
                    except Exception:
                        tname_addr = None

                if vtbl_addr is None and ctor is not None:
                    ctor_func = fm.getFunctionAt(af.getAddress(fmt(ctor)))
                    vtbl_addr = extract_vtbl_from_ctor(ifc, ctor_func)

                renames = {}
                if create is not None:
                    renames[create] = f"Create{t}Instance"
                renames[getter] = f"Get{t}ClassNamePointer"
                if ctor is not None:
                    renames[ctor] = f"Construct{t}BaseState"
                if dtor is not None:
                    renames[dtor] = f"Destruct{t}AndMaybeFree"

                for addr_int, new_name in renames.items():
                    f = fm.getFunctionAt(af.getAddress(fmt(addr_int)))
                    if f is None:
                        fn_fail += 1
                        print(f"[fn-miss] {fmt(addr_int)} {new_name}")
                        continue
                    if f.getName() == new_name:
                        fn_skip += 1
                        continue
                    try:
                        f.setName(new_name, SourceType.USER_DEFINED)
                        fn_ok += 1
                    except Exception as ex:
                        fn_fail += 1
                        print(f"[fn-fail] {fmt(addr_int)} -> {new_name} err={ex}")

                cls_ns = class_map.get(t)
                if cls_ns is not None:
                    for addr_int in renames.keys():
                        f = fm.getFunctionAt(af.getAddress(fmt(addr_int)))
                        if f is None:
                            continue
                        try:
                            cur_ns = f.getParentNamespace()
                            if cur_ns == cls_ns:
                                ns_skip += 1
                                continue
                            if cur_ns != global_ns and cur_ns.getName() != "Global":
                                ns_skip += 1
                                continue
                            f.setParentNamespace(cls_ns)
                            ns_ok += 1
                        except Exception as ex:
                            ns_fail += 1
                            print(f"[ns-fail] {fmt(addr_int)} {f.getName()} -> {t} err={ex}")

                labels = [(desc, f"g_pClassDesc{t}")]
                if tname_addr is not None:
                    labels.append((tname_addr, f"g_szTypeName{t}"))
                if vtbl_addr is not None:
                    labels.append((vtbl_addr, f"g_vtbl{t}"))

                for addr_int, label in labels:
                    addr = af.getAddress(fmt(addr_int))
                    syms = list(st.getSymbols(addr))
                    if any(s.getName() == label for s in syms):
                        lbl_skip += 1
                        continue
                    try:
                        sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                        sym.setPrimary()
                        lbl_ok += 1
                    except Exception as ex:
                        lbl_fail += 1
                        print(f"[lbl-fail] {fmt(addr_int)} {label} err={ex}")

                getter_func = fm.getFunctionAt(af.getAddress(fmt(getter)))
                if getter_func is not None:
                    getter_func.setComment(f"Returns class descriptor pointer for {t}.")
                    c_ok += 1
        finally:
            program.endTransaction(tx, True)

        program.save("apply class quads from csv", None)
        print(
            f"[done] rows={len(rows)} "
            f"fn_ok={fn_ok} fn_skip={fn_skip} fn_fail={fn_fail} "
            f"ns_ok={ns_ok} ns_skip={ns_skip} ns_fail={ns_fail} "
            f"lbl_ok={lbl_ok} lbl_skip={lbl_skip} lbl_fail={lbl_fail} "
            f"comments={c_ok}"
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
