#!/usr/bin/env python3
"""
Recover tiny linear stubs that are not inside any function.

Conservative acceptance:
  - start is outside any existing function
  - linear sequence length <= max-len
  - ends in RET or JMP
  - contains no conditional branches
  - contains at least one CALL/JMP

Usage:
  .venv/bin/python new_scripts/recover_tiny_no_func_linear_stubs.py
  .venv/bin/python new_scripts/recover_tiny_no_func_linear_stubs.py --apply --max-create 50
"""

from __future__ import annotations

import argparse
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


def flow_target(ins):
    try:
        flows = ins.getFlows()
        if flows is None or len(flows) != 1:
            return None
        return flows[0]
    except Exception:
        return None


def is_conditional_jump(mnem: str) -> bool:
    m = mnem.upper()
    if not m.startswith("J"):
        return False
    return m not in ("JMP",)


def is_allowed_mnemonic(mnem: str) -> bool:
    m = mnem.upper()
    if m in {
        "PUSH",
        "POP",
        "MOV",
        "LEA",
        "ADD",
        "SUB",
        "XOR",
        "OR",
        "AND",
        "TEST",
        "CMP",
        "CALL",
        "JMP",
        "RET",
        "NOP",
        "INC",
        "DEC",
    }:
        return True
    # Allow common x87 cleanup seen in tiny wrappers.
    if m.startswith("F"):
        return True
    return False


def propose_name(fm, start_int: int, seq) -> str:
    # Simple jmp-thunk form.
    if len(seq) <= 3:
        last = seq[-1]
        if str(last.getMnemonicString()).upper() == "JMP":
            tgt = flow_target(last)
            if tgt is not None:
                tf = fm.getFunctionAt(tgt)
                if tf is not None:
                    return f"thunk_{tf.getName()}_At{start_int:08x}"

    # Init stub form: ... CALL init ; PUSH dtor ; CALL register(0x005e7920) ; ...
    reg_call = None
    init_call = None
    for ins in seq:
        if str(ins.getMnemonicString()).upper() != "CALL":
            continue
        tgt = flow_target(ins)
        if tgt is None:
            continue
        toff = tgt.getOffset() & 0xFFFFFFFF
        if toff == 0x005E7920:
            reg_call = ins
            break
        init_call = ins
    if reg_call is not None and init_call is not None:
        tgt = flow_target(init_call)
        tf = fm.getFunctionAt(tgt) if tgt is not None else None
        if tf is not None:
            return f"InitStub_{tf.getName()}_At{start_int:08x}"

    return ""


def collect_stub(listing, fm, start_ins, max_len: int):
    seq = []
    cur = start_ins
    has_branch = False
    end_reason = ""
    for _ in range(max_len):
        if cur is None:
            end_reason = "no_next"
            break
        if fm.getFunctionContaining(cur.getAddress()) is not None:
            end_reason = "entered_function"
            break
        m = str(cur.getMnemonicString()).upper()
        if not is_allowed_mnemonic(m):
            end_reason = f"bad_mnemonic:{m}"
            break
        if is_conditional_jump(m):
            end_reason = "conditional_jump"
            break

        seq.append(cur)
        if m in ("CALL", "JMP"):
            has_branch = True
        if m in ("RET", "JMP"):
            end_reason = m
            break
        cur = listing.getInstructionAfter(cur.getAddress())

    if not seq:
        return None, "empty"
    if end_reason not in ("RET", "JMP"):
        return None, end_reason or "not_terminated"
    if not has_branch:
        return None, "no_branch"
    return seq, end_reason


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Create functions")
    ap.add_argument("--max-len", type=int, default=16, help="Max instructions per stub")
    ap.add_argument("--max-create", type=int, default=100, help="Create limit when --apply")
    ap.add_argument("--max-print", type=int, default=200, help="Print limit")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.symbol import SourceType

        listing = program.getListing()
        fm = program.getFunctionManager()
        api = FlatProgramAPI(program)

        starts = []
        seen = set()

        it = listing.getInstructions(True)
        while it.hasNext():
            ins = it.next()
            a = ins.getAddress()
            ai = a.getOffset() & 0xFFFFFFFF
            if ai in seen:
                continue
            if fm.getFunctionContaining(a) is not None:
                continue

            prev = listing.getInstructionBefore(a)
            if prev is not None:
                pm = str(prev.getMnemonicString()).upper()
                if pm != "RET" and fm.getFunctionContaining(prev.getAddress()) is None:
                    continue

            seq, reason = collect_stub(listing, fm, ins, args.max_len)
            if seq is None:
                continue
            seen.add(ai)
            end_mnem = str(seq[-1].getMnemonicString()).upper()
            name_hint = propose_name(fm, ai, seq)
            starts.append(
                {
                    "start": ai,
                    "len": len(seq),
                    "end": end_mnem,
                    "name_hint": name_hint,
                    "first_ins": str(seq[0]),
                    "last_ins": str(seq[-1]),
                }
            )

        starts.sort(key=lambda r: r["start"])
        print(
            f"[summary] candidates={len(starts)} max_len={args.max_len} apply={args.apply} "
            f"max_create={args.max_create}"
        )
        for r in starts[: args.max_print]:
            print(
                f"0x{r['start']:08x} len={r['len']} end={r['end']} "
                f"name_hint={r['name_hint'] or '<none>'} "
                f"first=\"{r['first_ins']}\" last=\"{r['last_ins']}\""
            )
        if len(starts) > args.max_print:
            print(f"... ({len(starts) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to create functions")
            return 0

        tx = program.startTransaction("Recover tiny no-func linear stubs")
        created = skipped = failed = renamed = 0
        try:
            for r in starts:
                if args.max_create > 0 and created >= args.max_create:
                    break
                addr = program.getAddressFactory().getAddress(f"0x{r['start']:08x}")
                if fm.getFunctionContaining(addr) is not None:
                    skipped += 1
                    continue
                try:
                    api.disassemble(addr)
                    fn = api.createFunction(addr, None)
                    if fn is None:
                        fn = fm.getFunctionAt(addr)
                    if fn is None:
                        failed += 1
                        continue
                    created += 1
                    hint = r["name_hint"]
                    if hint and fn.getName().startswith("FUN_"):
                        fn.setName(hint, SourceType.USER_DEFINED)
                        renamed += 1
                except Exception as ex:
                    failed += 1
                    print(f"[fail] 0x{r['start']:08x} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("recover tiny no-func linear stubs", None)
        print(f"[done] created={created} renamed={renamed} skipped={skipped} failed={failed}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
