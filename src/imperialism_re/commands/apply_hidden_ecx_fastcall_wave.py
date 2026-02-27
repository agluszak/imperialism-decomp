#!/usr/bin/env python3
"""
Apply conservative calling-convention signatures for global functions with hidden in_ECX artifacts.

Input CSV format (from scan_hidden_decomp_params.py):
  - address,name,namespace,signature,in_ecx_hits,in_stack_arg_hits,in_stack_local_hits,stack_arg_slot_list

Default safety gates:
  - global namespace only
  - in_ECX >= threshold
  - in_stack_local_hits == 0
  - signature currently ends with "(void)"
  - contiguous positive stack slots (0x4..max)
  - bounded stack arg count
  - require thunk/core pairing by base name

Behavior:
  - keeps current return type unchanged
  - supports:
      - fastcall: ecxArg:int, [edxArg:int], stack args
      - thiscall: pThis:void*, stack args
"""

from __future__ import annotations

import argparse
import csv
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

def base_name(name: str) -> str:
    if name.startswith("thunk_"):
        return name[len("thunk_") :]
    return name

@dataclass
class Candidate:
    address: int
    name: str
    namespace: str
    in_ecx_hits: int
    in_stack_arg_hits: int
    slot_list: list[int]
    stack_param_count: int
    signature: str
    pair_ok: bool

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument("--min-ecx-hits", type=int, default=10)
    ap.add_argument("--max-stack-params", type=int, default=2)
    ap.add_argument("--min-stack-hits", type=int, default=1)
    ap.add_argument("--allow-zero-stack", action="store_true", help="Allow candidates with zero stack slots")
    ap.add_argument(
        "--allow-gapped-slots",
        action="store_true",
        help="Allow non-contiguous positive stack slots and infer stack arg count by max slot/4",
    )
    ap.add_argument("--require-pair", action="store_true", help="Require thunk/core pair")
    ap.add_argument("--include-edx-param", action="store_true", help="Add explicit edxArg too")
    ap.add_argument(
        "--calling-convention",
        choices=["fastcall", "thiscall"],
        default="fastcall",
        help="Calling convention to apply",
    )
    ap.add_argument("--allow-nonvoid-signature", action="store_true")
    ap.add_argument("--max-print", type=int, default=200)
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    names = {(r.get("name") or "").strip() for r in rows}

    cands: list[Candidate] = []
    for r in rows:
        try:
            addr = parse_hex((r.get("address") or "").strip())
            name = (r.get("name") or "").strip()
            ns = (r.get("namespace") or "").strip()
            sig = (r.get("signature") or "").strip().strip('"')
            ecx = int((r.get("in_ecx_hits") or "0").strip() or "0")
            stack_hits = int((r.get("in_stack_arg_hits") or "0").strip() or "0")
            stack_locals = int((r.get("in_stack_local_hits") or "0").strip() or "0")
            slots = parse_slots(r.get("stack_arg_slot_list") or "")
        except Exception:
            continue

        if ns:
            continue
        if ecx < args.min_ecx_hits:
            continue
        if stack_hits < args.min_stack_hits:
            continue
        if stack_locals != 0:
            continue
        if not args.allow_nonvoid_signature and "(void)" not in sig:
            continue
        if not slots:
            if not args.allow_zero_stack:
                continue
            stack_count = 0
        else:
            max_slot = max(slots)
            if max_slot % 4 != 0:
                continue
            if not contiguous_slots(slots) and not args.allow_gapped_slots:
                continue
            stack_count = max_slot // 4
            if stack_count <= 0 or stack_count > args.max_stack_params:
                continue

        b = base_name(name)
        pair_ok = (f"thunk_{b}" in names) and (b in names)
        if args.require_pair and not pair_ok:
            continue

        cands.append(
            Candidate(
                address=addr,
                name=name,
                namespace=ns,
                in_ecx_hits=ecx,
                in_stack_arg_hits=stack_hits,
                slot_list=slots,
                stack_param_count=stack_count,
                signature=sig,
                pair_ok=pair_ok,
            )
        )

    cands.sort(key=lambda c: (-c.in_ecx_hits, -c.in_stack_arg_hits, c.address))
    print(
        f"[candidates] {len(cands)} min_ecx={args.min_ecx_hits} "
        f"max_stack_params={args.max_stack_params} require_pair={int(args.require_pair)} "
        f"include_edx={int(args.include_edx_param)} cc={args.calling_convention}"
        f" allow_gapped_slots={int(args.allow_gapped_slots)}"
    )
    for c in cands[: args.max_print]:
        slots_txt = ";".join(f"0x{x:08x}" for x in c.slot_list)
        print(
            f"  0x{c.address:08x} {c.name} ecx={c.in_ecx_hits} "
            f"stack_hits={c.in_stack_arg_hits} stack_params={c.stack_param_count} "
            f"pair={int(c.pair_ok)} slots={slots_txt}"
        )
    if len(cands) > args.max_print:
        print(f"  ... ({len(cands) - args.max_print} more)")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    with open_program(root) as program:
        from ghidra.program.model.data import IntegerDataType, PointerDataType, VoidDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        tx = program.startTransaction("Apply hidden ecx fastcall wave")
        ok = skip = fail = miss = 0
        try:
            for c in cands:
                f = fm.getFunctionAt(af.getAddress(f"0x{c.address:08x}"))
                if f is None:
                    miss += 1
                    continue
                try:
                    old_sig = str(f.getSignature())
                    if args.calling_convention == "thiscall":
                        f.setCallingConvention("__thiscall")
                        cur_params = list(f.getParameters())
                        if cur_params:
                            this_dt = cur_params[0].getDataType()
                        else:
                            this_dt = PointerDataType(VoidDataType.dataType)
                        params = [
                            ParameterImpl(
                                "this",
                                this_dt,
                                program,
                                SourceType.USER_DEFINED,
                            )
                        ]
                    else:
                        f.setCallingConvention("__fastcall")
                        params = [
                            ParameterImpl("ecxArg", IntegerDataType.dataType, program, SourceType.USER_DEFINED)
                        ]
                        if args.include_edx_param:
                            params.append(
                                ParameterImpl("edxArg", IntegerDataType.dataType, program, SourceType.USER_DEFINED)
                            )
                    for i in range(c.stack_param_count):
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
                    print(f"[fail] 0x{c.address:08x} {c.name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply hidden ecx fastcall wave", None)
        print(f"[done] ok={ok} skip={skip} fail={fail} miss={miss}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
