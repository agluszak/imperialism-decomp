#!/usr/bin/env python3
"""
Apply conservative signature fixes from a hidden-param artifact CSV.

Input CSV format:
  - address
  - name
  - namespace
  - signature
  - in_ecx_hits
  - in_stack_arg_hits
  - in_stack_local_hits
  - stack_arg_slot_list

Default safety gates (tuned for first-pass burn-down):
  - global namespace only
  - in_ECX == 0
  - in_stack_local_hits == 0
  - signature currently ends with "(void)"
  - stack slots contiguous: 0x4,0x8,...,max
  - max param count bounded

Behavior:
  - keeps current return type unchanged
  - sets calling convention to __cdecl
  - replaces params with int arg1..argN
"""

from __future__ import annotations

import argparse
import csv
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


@dataclass
class Candidate:
    address: int
    name: str
    namespace: str
    in_ecx_hits: int
    in_stack_arg_hits: int
    slot_list: list[int]
    param_count: int
    signature: str


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="Hidden-param CSV from scan_hidden_decomp_params.py")
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument("--min-stack-hits", type=int, default=4)
    ap.add_argument("--max-params", type=int, default=6)
    ap.add_argument("--max-print", type=int, default=220)
    ap.add_argument("--allow-ecx", action="store_true", help="Also include rows with in_ECX > 0")
    ap.add_argument("--allow-namespaced", action="store_true", help="Also include non-global namespace rows")
    ap.add_argument(
        "--allow-nonvoid-signature",
        action="store_true",
        help="Allow functions whose current signature is not '(void)'",
    )
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
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

        if stack_hits < args.min_stack_hits:
            continue
        if stack_locals != 0:
            continue
        if not args.allow_ecx and ecx > 0:
            continue
        if not args.allow_namespaced and ns:
            continue
        if not args.allow_nonvoid_signature and "(void)" not in sig:
            continue
        if not slots or not contiguous_slots(slots):
            continue

        param_count = max(slots) // 4
        if param_count <= 0 or param_count > args.max_params:
            continue

        cands.append(
            Candidate(
                address=addr,
                name=name,
                namespace=ns,
                in_ecx_hits=ecx,
                in_stack_arg_hits=stack_hits,
                slot_list=slots,
                param_count=param_count,
                signature=sig,
            )
        )

    cands.sort(
        key=lambda c: (
            -c.in_stack_arg_hits,
            c.address,
        )
    )

    print(
        f"[candidates] {len(cands)} min_stack_hits={args.min_stack_hits} "
        f"max_params={args.max_params} allow_ecx={int(args.allow_ecx)} "
        f"allow_namespaced={int(args.allow_namespaced)}"
    )
    for c in cands[: args.max_print]:
        slots_txt = ";".join(f"0x{x:08x}" for x in c.slot_list)
        print(
            f"  0x{c.address:08x} {c.name} ns={c.namespace or '<global>'} "
            f"stack_hits={c.in_stack_arg_hits} params={c.param_count} slots={slots_txt}"
        )
    if len(cands) > args.max_print:
        print(f"  ... ({len(cands) - args.max_print} more)")

    if not args.apply:
        print("[dry-run] pass --apply to write changes")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import IntegerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        tx = program.startTransaction("Apply hidden param signature wave")
        ok = skip = fail = miss = 0
        try:
            for c in cands:
                f = fm.getFunctionAt(af.getAddress(f"0x{c.address:08x}"))
                if f is None:
                    miss += 1
                    continue
                try:
                    old_sig = str(f.getSignature())
                    f.setCallingConvention("__cdecl")
                    params = [
                        ParameterImpl(
                            f"arg{i+1}",
                            IntegerDataType.dataType,
                            program,
                            SourceType.USER_DEFINED,
                        )
                        for i in range(c.param_count)
                    ]
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

        program.save("apply hidden param signature wave", None)
        print(f"[done] ok={ok} skip={skip} fail={fail} miss={miss}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
