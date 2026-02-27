#!/usr/bin/env python3
"""
Add missing stack parameters to __thiscall class methods from hidden-param CSV.

Input CSV should come from scan_hidden_decomp_params.py.

Conservative gates:
- namespace matches --class-regex
- in_ECX == 0 (unless --allow-ecx)
- in_stack_local_hits == 0
- stack_arg_slot_list contiguous 0x4..max step 4
  (or --allow-gapped-slots to infer by max slot)
- function signature is __thiscall with exactly one parameter (this/pThis)
- inferred param count <= --max-params

Behavior:
- keeps function return type and calling convention
- preserves first parameter type/name
- appends int arg1..argN for inferred stack args

Usage:
  uv run impk apply_thiscall_stack_params_from_hidden_csv \
    --in-csv tmp_decomp/batch632_hidden_class_sample.csv
  uv run impk apply_thiscall_stack_params_from_hidden_csv \
    --in-csv tmp_decomp/batch632_hidden_class_sample.csv --apply
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

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

@dataclass
class Candidate:
    address: int
    namespace: str
    name: str
    stack_hits: int
    add_count: int
    slots: list[int]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--class-regex", default=r"^T")
    ap.add_argument(
        "--allow-global",
        action="store_true",
        help="Allow global-namespace __thiscall functions (ignore --class-regex for empty namespace)",
    )
    ap.add_argument("--min-stack-hits", type=int, default=8)
    ap.add_argument("--max-params", type=int, default=6)
    ap.add_argument("--allow-ecx", action="store_true")
    ap.add_argument(
        "--allow-gapped-slots",
        action="store_true",
        help="Allow non-contiguous positive stack slots and infer arg count by max slot/4",
    )
    ap.add_argument("--max-print", type=int, default=220)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
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
            ns = (r.get("namespace") or "").strip()
            name = (r.get("name") or "").strip()
            sig = (r.get("signature") or "").strip().strip('"')
            ecx = int((r.get("in_ecx_hits") or "0").strip() or "0")
            stack_hits = int((r.get("in_stack_arg_hits") or "0").strip() or "0")
            stack_locals = int((r.get("in_stack_local_hits") or "0").strip() or "0")
            slots = parse_slots(r.get("stack_arg_slot_list") or "")
        except Exception:
            continue

        if ns:
            if not class_re.search(ns):
                continue
        else:
            if not args.allow_global:
                continue
        if "__thiscall" not in sig:
            continue
        # expected one explicit this param in signature text.
        if sig.count(",") != 0:
            continue
        if "(void)" in sig:
            continue
        if (not args.allow_ecx) and ecx > 0:
            continue
        if stack_locals != 0:
            continue
        if stack_hits < args.min_stack_hits:
            continue
        if not slots:
            continue
        max_slot = max(slots)
        if max_slot % 4 != 0:
            continue
        if not contiguous_slots(slots) and not args.allow_gapped_slots:
            continue
        add_count = max_slot // 4
        if add_count <= 0 or add_count > args.max_params:
            continue

        cands.append(
            Candidate(
                address=addr,
                namespace=ns,
                name=name,
                stack_hits=stack_hits,
                add_count=add_count,
                slots=slots,
            )
        )

    cands.sort(key=lambda c: (-c.stack_hits, c.address))
    print(
        f"[candidates] {len(cands)} class_regex={args.class_regex} "
        f"allow_global={int(args.allow_global)} "
        f"min_stack_hits={args.min_stack_hits} max_params={args.max_params} "
        f"allow_ecx={int(args.allow_ecx)} "
        f"allow_gapped_slots={int(args.allow_gapped_slots)}"
    )
    for c in cands[: args.max_print]:
        slots_txt = ";".join(f"0x{x:08x}" for x in c.slots)
        print(
            f"  0x{c.address:08x} {c.namespace}::{c.name} "
            f"stack_hits={c.stack_hits} add_count={c.add_count} slots={slots_txt}"
        )
    if len(cands) > args.max_print:
        print(f"  ... ({len(cands) - args.max_print} more)")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    with open_program(root) as program:
        from ghidra.program.model.data import IntegerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        tx = program.startTransaction("Apply thiscall stack params from hidden CSV")
        ok = skip = fail = miss = 0
        try:
            for c in cands:
                f = fm.getFunctionAt(af.getAddress(f"0x{c.address:08x}"))
                if f is None:
                    miss += 1
                    continue
                try:
                    params = list(f.getParameters())
                    if len(params) != 1:
                        skip += 1
                        continue
                    old_sig = str(f.getSignature())
                    p0 = params[0]
                    this_name = p0.getName() or "pThis"
                    new_params = [
                        ParameterImpl(this_name, p0.getDataType(), program, SourceType.USER_DEFINED)
                    ]
                    for i in range(c.add_count):
                        new_params.append(
                            ParameterImpl(f"arg{i+1}", IntegerDataType.dataType, program, SourceType.USER_DEFINED)
                        )
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] 0x{c.address:08x} {c.namespace}::{c.name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply thiscall stack params from hidden csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail} miss={miss}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
