#!/usr/bin/env python3
"""
Promote class-namespaced zero-param cdecl functions to __thiscall with stack args,
using hidden-parameter artifact CSV evidence.

Input CSV: scan_hidden_decomp_params.py output.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
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


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def parse_slots(raw: str) -> list[int]:
    txt = (raw or "").strip()
    if not txt:
        return []
    out: list[int] = []
    for part in txt.split(";"):
        p = part.strip()
        if not p:
            continue
        out.append(parse_hex(p))
    return sorted(set(out))


def contiguous_slots(slots: list[int]) -> bool:
    if not slots:
        return False
    expected = list(range(0x4, max(slots) + 1, 4))
    return slots == expected


def find_datatype_by_name(dtm, name: str):
    from ghidra.program.model.data import CategoryPath

    dt = dtm.getDataType(CategoryPath("/imperialism/classes"), name)
    if dt is not None:
        return dt
    it = dtm.getAllDataTypes()
    while it.hasNext():
        cand = it.next()
        if cand.getName() == name:
            return cand
    return None


@dataclass
class Candidate:
    address: int
    name: str
    cls: str
    stack_hits: int
    slots: list[int]
    add_count: int
    signature: str


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--class-regex", default=r"^(TMapDialog|TMapMaker|TViewMgr|TDiplomacyMapView|TMapUberPicture)$")
    ap.add_argument("--min-stack-hits", type=int, default=8)
    ap.add_argument("--max-params", type=int, default=6)
    ap.add_argument("--allow-ecx", action="store_true", help="Allow rows with in_ECX > 0")
    ap.add_argument("--max-print", type=int, default=220)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    class_re = re.compile(args.class_regex)
    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    cands: list[Candidate] = []
    for r in rows:
        try:
            addr = parse_hex((r.get("address") or "").strip())
            name = (r.get("name") or "").strip()
            cls = (r.get("namespace") or "").strip()
            sig = (r.get("signature") or "").strip().strip('"')
            ecx = int((r.get("in_ecx_hits") or "0").strip() or "0")
            stack_hits = int((r.get("in_stack_arg_hits") or "0").strip() or "0")
            stack_locals = int((r.get("in_stack_local_hits") or "0").strip() or "0")
            slots = parse_slots(r.get("stack_arg_slot_list") or "")
        except Exception:
            continue

        if not cls or not class_re.search(cls):
            continue
        if (not args.allow_ecx) and ecx != 0:
            continue
        if stack_locals != 0:
            continue
        if stack_hits < args.min_stack_hits:
            continue
        if "__cdecl" not in sig:
            continue
        if "(void)" not in sig:
            continue
        if not slots or not contiguous_slots(slots):
            continue
        add_count = max(slots) // 4
        if add_count <= 0 or add_count > args.max_params:
            continue

        cands.append(
            Candidate(
                address=addr,
                name=name,
                cls=cls,
                stack_hits=stack_hits,
                slots=slots,
                add_count=add_count,
                signature=sig,
            )
        )

    cands.sort(key=lambda c: (-c.stack_hits, c.address))
    print(
        f"[candidates] {len(cands)} class_regex={args.class_regex} "
        f"min_stack_hits={args.min_stack_hits} max_params={args.max_params} "
        f"allow_ecx={int(args.allow_ecx)}"
    )
    for c in cands[: args.max_print]:
        slots_txt = ";".join(f"0x{x:08x}" for x in c.slots)
        print(
            f"  0x{c.address:08x} {c.cls}::{c.name} "
            f"stack_hits={c.stack_hits} add_count={c.add_count} slots={slots_txt}"
        )
    if len(cands) > args.max_print:
        print(f"  ... ({len(cands) - args.max_print} more)")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import IntegerDataType, PointerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        class_ptr_cache = {}
        tx = program.startTransaction("Apply class method stack params from hidden CSV")
        ok = skip = fail = miss = 0
        try:
            for c in cands:
                f = fm.getFunctionAt(af.getAddress(f"0x{c.address:08x}"))
                if f is None:
                    miss += 1
                    continue
                try:
                    if c.cls not in class_ptr_cache:
                        cdt = find_datatype_by_name(dtm, c.cls)
                        if cdt is None:
                            class_ptr_cache[c.cls] = None
                        else:
                            class_ptr_cache[c.cls] = PointerDataType(cdt)
                    p_this_dt = class_ptr_cache[c.cls]
                    if p_this_dt is None:
                        fail += 1
                        print(f"[fail] 0x{c.address:08x} {c.cls}::{c.name} err=missing class datatype")
                        continue

                    old_sig = str(f.getSignature())
                    f.setCallingConvention("__thiscall")
                    params = [
                        ParameterImpl("pThis", p_this_dt, program, SourceType.USER_DEFINED)
                    ]
                    for i in range(c.add_count):
                        params.append(
                            ParameterImpl(f"arg{i+1}", IntegerDataType.dataType, program, SourceType.USER_DEFINED)
                        )
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        params,
                    )
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{c.address:08x} {c.cls}::{c.name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply class method stack params from hidden csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail} miss={miss}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
