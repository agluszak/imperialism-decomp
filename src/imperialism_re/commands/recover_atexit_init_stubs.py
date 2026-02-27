#!/usr/bin/env python3
"""
Recover tiny no-function init stubs that register dtors through a known helper.

Pattern (typical):
  MOV ECX, <global_state>
  CALL <init_fn>
  PUSH <dtor_fn>
  CALL <register_fn>    ; default: 0x005e7920
  ADD ESP, 4
  RET

Usage:
  uv run impk recover_atexit_init_stubs
  uv run impk recover_atexit_init_stubs --apply
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def flow_target(ins):
    flows = ins.getFlows()
    if flows is None or len(flows) != 1:
        return None
    return flows[0]

def ins_text(ins):
    return str(ins) if ins is not None else ""

def parse_push_imm_addr(ins):
    if ins is None:
        return None
    if str(ins.getMnemonicString()).upper() != "PUSH":
        return None
    try:
        scalar = ins.getScalar(0)
        if scalar is None:
            return None
        return scalar.getValue() & 0xFFFFFFFF
    except Exception:
        return None

def is_call_to(ins, target_addr):
    if ins is None:
        return False
    if str(ins.getMnemonicString()).upper() != "CALL":
        return False
    ft = flow_target(ins)
    if ft is None:
        return False
    return (ft.getOffset() & 0xFFFFFFFF) == target_addr

def find_stub_start(listing, call_register_ins, max_back: int):
    # Prefer "first instruction after nearest RET" as stub start.
    cur = call_register_ins
    seen = [call_register_ins]
    for _ in range(max_back):
        prev = listing.getInstructionBefore(cur.getAddress())
        if prev is None:
            break
        seen.append(prev)
        if str(prev.getMnemonicString()).upper() == "RET":
            nxt = listing.getInstructionAfter(prev.getAddress())
            return nxt
        cur = prev
    return seen[-1]

def collect_linear_until_ret(listing, start_ins, max_fwd: int):
    seq = [start_ins]
    cur = start_ins
    for _ in range(max_fwd):
        if str(cur.getMnemonicString()).upper() == "RET":
            break
        nxt = listing.getInstructionAfter(cur.getAddress())
        if nxt is None:
            break
        seq.append(nxt)
        cur = nxt
    return seq

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Create missing functions")
    ap.add_argument(
        "--register-target",
        default="0x005e7920",
        help="Address of dtor-register helper (default: 0x005e7920)",
    )
    ap.add_argument("--max-back", type=int, default=12, help="Max backward instructions")
    ap.add_argument("--max-forward", type=int, default=20, help="Max forward instructions")
    ap.add_argument(
        "--max-pre-register-ins",
        type=int,
        default=10,
        help="Max linear instructions from inferred start to register-call",
    )
    ap.add_argument("--max-print", type=int, default=200, help="Maximum rows to print")
    ap.add_argument(
        "--create-dtor-stubs",
        action="store_true",
        help="When --apply, also create missing dtor-wrapper functions from PUSH immediate targets",
    )
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    register_target = parse_hex(args.register_target)
    root = resolve_project_root(args.project_root)

    with open_program(root) as program:
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        mem = program.getMemory()
        api = FlatProgramAPI(program)

        reg_addr = af.getAddress(f"0x{register_target:08x}")
        refs = list(rm.getReferencesTo(reg_addr))
        candidates = []
        seen_starts = set()

        for ref in refs:
            from_addr = ref.getFromAddress()
            call_reg = listing.getInstructionAt(from_addr)
            if not is_call_to(call_reg, register_target):
                continue

            start_ins = find_stub_start(listing, call_reg, args.max_back)
            if start_ins is None:
                continue
            seq = collect_linear_until_ret(listing, start_ins, args.max_forward)
            if call_reg not in seq:
                continue

            start_addr = start_ins.getAddress()
            start_int = start_addr.getOffset() & 0xFFFFFFFF
            if start_int in seen_starts:
                continue
            seen_starts.add(start_int)

            # Identify primary init-call before register call.
            init_call = None
            dtor_push = None
            pre_seq = []
            for ins in seq:
                pre_seq.append(ins)
                if ins == call_reg:
                    break
                if str(ins.getMnemonicString()).upper() == "CALL":
                    init_call = ins
            prev = listing.getInstructionBefore(call_reg.getAddress())
            if prev is not None and str(prev.getMnemonicString()).upper() == "PUSH":
                dtor_push = prev
            dtor_addr_int = parse_push_imm_addr(dtor_push)

            # Conservative stub-shape guard: no unconditional jump/ret before register call,
            # and keep short distance from inferred start to register call.
            if len(pre_seq) > args.max_pre_register_ins:
                continue
            bad_pre = False
            for ins in pre_seq[:-1]:
                m = str(ins.getMnemonicString()).upper()
                if m in ("JMP", "RET"):
                    bad_pre = True
                    break
            if bad_pre:
                continue
            if init_call is None:
                continue

            init_target = ""
            init_name = ""
            if init_call is not None:
                itgt = flow_target(init_call)
                if itgt is not None:
                    init_target = str(itgt)
                    itf = fm.getFunctionAt(itgt)
                    init_name = itf.getName() if itf is not None else ""

            existing = fm.getFunctionContaining(start_addr)
            existing_name = existing.getName() if existing is not None else ""
            fn_len = len(seq)
            has_ret = any(str(ins.getMnemonicString()).upper() == "RET" for ins in seq)
            block = mem.getBlock(start_addr)
            is_exec = bool(block is not None and block.isExecute())
            if not has_ret or not is_exec:
                continue

            candidates.append(
                {
                    "start_addr": f"0x{start_int:08x}",
                    "existing_function": existing_name,
                    "init_target": init_target,
                    "init_name": init_name,
                    "register_call_addr": str(call_reg.getAddress()),
                    "dtor_push": ins_text(dtor_push),
                    "dtor_addr": "" if dtor_addr_int is None else f"0x{dtor_addr_int:08x}",
                    "start_ins": ins_text(start_ins),
                    "instruction_count": str(fn_len),
                }
            )

        candidates.sort(key=lambda r: int(r["start_addr"], 16))
        print(
            f"[summary] register_target=0x{register_target:08x} "
            f"candidates={len(candidates)} apply={args.apply}"
        )
        for row in candidates[: args.max_print]:
            print(
                f"{row['start_addr']} existing={row['existing_function'] or '<no_func>'} "
                f"init={row['init_target']} {row['init_name']} "
                f"reg_call={row['register_call_addr']} "
                f"dtor={row['dtor_addr'] or '<none>'} "
                f"dtor_push=\"{row['dtor_push']}\" "
                f"len={row['instruction_count']}"
            )
        if len(candidates) > args.max_print:
            print(f"... ({len(candidates) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to create missing functions")
            return 0

        tx = program.startTransaction("Recover atexit init stubs")
        created = skipped = failed = renamed = 0
        dtor_created = dtor_renamed = dtor_skipped = dtor_failed = 0
        try:
            for row in candidates:
                a = parse_hex(row["start_addr"])
                addr = af.getAddress(f"0x{a:08x}")
                cur = fm.getFunctionContaining(addr)
                if cur is not None:
                    skipped += 1
                else:
                    try:
                        api.disassemble(addr)
                        fn = api.createFunction(addr, None)
                        if fn is None:
                            fn = fm.getFunctionAt(addr)
                        if fn is None:
                            failed += 1
                            continue
                        created += 1
                        if fn.getName().startswith("FUN_"):
                            init_name = row["init_name"] or "UnknownInit"
                            safe = "".join(
                                ch if ch.isalnum() or ch == "_" else "_" for ch in init_name
                            )
                            new_name = f"InitStub_{safe}_At{a:08x}"
                            fn.setName(new_name, SourceType.USER_DEFINED)
                            renamed += 1
                    except Exception as ex:
                        failed += 1
                        print(f"[fail] {row['start_addr']} err={ex}")

                if not args.create_dtor_stubs:
                    continue
                dtor_addr_txt = (row.get("dtor_addr") or "").strip()
                if not dtor_addr_txt:
                    continue
                try:
                    da = parse_hex(dtor_addr_txt)
                except Exception:
                    dtor_failed += 1
                    continue
                dtor_addr = af.getAddress(f"0x{da:08x}")
                dcur = fm.getFunctionContaining(dtor_addr)
                if dcur is not None:
                    dtor_skipped += 1
                    continue
                try:
                    api.disassemble(dtor_addr)
                    dfn = api.createFunction(dtor_addr, None)
                    if dfn is None:
                        dfn = fm.getFunctionAt(dtor_addr)
                    if dfn is None:
                        dtor_failed += 1
                        continue
                    dtor_created += 1
                    if dfn.getName().startswith("FUN_"):
                        init_name = row["init_name"] or "UnknownInit"
                        safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in init_name)
                        dname = f"DtorStub_{safe}_At{da:08x}"
                        dfn.setName(dname, SourceType.USER_DEFINED)
                        dtor_renamed += 1
                except Exception as ex:
                    dtor_failed += 1
                    print(f"[dtor-fail] {dtor_addr_txt} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("recover atexit init stubs", None)
        print(
            f"[done] created={created} renamed={renamed} skipped={skipped} failed={failed} "
            f"dtor_created={dtor_created} dtor_renamed={dtor_renamed} "
            f"dtor_skipped={dtor_skipped} dtor_failed={dtor_failed}"
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
