#!/usr/bin/env python3
"""Read-only: decode an MSVC500 switch jump table into case -> target rows.

The turn-event dispatchers and screen-builder factories all lower `switch` to the
classic MSVC5 pattern, frequently inside Ghidra code gaps where nothing is
structured:

    cmp   eax, 0x18                      ; bound (case count - 1)
    ja    default
    xor   edx, edx
    mov   dl, byte ptr [eax + IDXTABLE]  ; optional two-level index bytes
    jmp   dword ptr [edx*4 + TABLE]      ; dword target table

Given the address of the indirect `jmp`, this reads the instruction bytes with
capstone (so it works in Ghidra gaps), extracts TABLE from the operand, walks the
dword entries while they look like code addresses, detects a trailing index-byte
table (MSVC emits it directly after the target table), and prints each case with
the containing function of its target. Worked example: `jumptable 0x5db695`
decodes TViewMgr::HandleTurnStateExitAndPostFollowupEventCode's followup-event
poster (targets at 0x5db6fc, index bytes at 0x5db710).

Bytes are read one at a time via Memory.getByte — do NOT bulk-read with
Memory.getBytes + a Python buffer (silent all-zero reads; see raw_disasm.py).

usage: jumptable 0xJMPADDR [--cases N]
       jumptable --table 0xADDR [--cases N] [--index 0xADDR --index-count N]
"""

from __future__ import annotations

import argparse
import re
import sys

from tools.common import ghidra_env

MAX_AUTO_CASES = 64
JMP_TABLE_OPERAND_RE = re.compile(
    r"dword ptr \[(?:e[a-z]{2}\*4 \+ (0x[0-9a-f]+)|(0x[0-9a-f]+) \+ e[a-z]{2}\*4)\]"
)


def parse_jmp_table_operand(op_str: str) -> int | None:
    """Extract the table address from a capstone `jmp dword ptr [reg*4 + imm]` operand."""
    m = JMP_TABLE_OPERAND_RE.search(op_str)
    if not m:
        return None
    return int(m.group(1) or m.group(2), 16)


def looks_like_code_address(value: int, code_min: int, code_max: int) -> bool:
    return code_min <= value <= code_max


def _read_bytes(mem, af, addr_int: int, count: int) -> bytes:
    addr = af.getAddress(addr_int)
    return bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(count))


def _decode_jmp(mem, af, jmp_addr: int) -> int | None:
    import capstone

    data = _read_bytes(mem, af, jmp_addr, 8)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for ins in md.disasm(data, jmp_addr):
        if ins.mnemonic != "jmp":
            print(f"instruction at 0x{jmp_addr:08x} is `{ins.mnemonic} {ins.op_str}`, not an indirect jmp",
                  file=sys.stderr)
            return None
        table = parse_jmp_table_operand(ins.op_str)
        if table is None:
            print(f"could not parse a `[reg*4 + table]` operand from `{ins.op_str}`", file=sys.stderr)
        return table
    print(f"could not disassemble at 0x{jmp_addr:08x}", file=sys.stderr)
    return None


def run(program, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="jumptable", add_help=True)
    parser.add_argument("jmp_addr", nargs="?", help="address of the indirect jmp (hex)")
    parser.add_argument("--table", help="dword target-table address (hex), bypassing jmp decoding")
    parser.add_argument("--cases", type=int, default=0, help="explicit target count (default: auto)")
    parser.add_argument("--index", help="index-byte table address (hex; default: auto-detect after table)")
    parser.add_argument("--index-count", type=int, default=0, help="index-byte count (with --index)")
    args = parser.parse_args(argv)

    if not args.jmp_addr and not args.table:
        parser.print_usage(sys.stderr)
        return 2

    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()

    # Code-address plausibility window: the executable block bounds.
    code_min, code_max = None, None
    for block in mem.getBlocks():
        if block.isExecute():
            lo = block.getStart().getOffset()
            hi = block.getEnd().getOffset()
            code_min = lo if code_min is None else min(code_min, lo)
            code_max = hi if code_max is None else max(code_max, hi)
    if code_min is None or code_max is None:
        print("no executable memory blocks found", file=sys.stderr)
        return 1

    if args.table:
        table_addr = int(args.table, 16)
    else:
        table = _decode_jmp(mem, af, int(args.jmp_addr, 16))
        if table is None:
            return 1
        table_addr = table

    # Read target dwords while they stay plausible code addresses.
    max_cases = args.cases if args.cases > 0 else MAX_AUTO_CASES
    targets: list[int] = []
    for i in range(max_cases):
        raw = _read_bytes(mem, af, table_addr + i * 4, 4)
        value = int.from_bytes(raw, "little")
        if args.cases <= 0 and not looks_like_code_address(value, code_min, code_max):
            break
        targets.append(value)
    if not targets:
        print(f"no plausible code addresses at table 0x{table_addr:08x}", file=sys.stderr)
        return 1

    print(f"target table 0x{table_addr:08x}: {len(targets)} entries"
          + ("" if args.cases > 0 else f" (auto-bounded; --cases to override, cap {MAX_AUTO_CASES})"))
    for i, tgt in enumerate(targets):
        fn = fm.getFunctionContaining(af.getAddress(tgt))
        where = f"{fn.getName()} (entry {fn.getEntryPoint()})" if fn else "(Ghidra gap — try raw-disasm)"
        print(f"  target[{i}] = 0x{tgt:08x}  {where}")

    # Two-level form: index bytes follow the target table (or come from --index).
    index_addr = int(args.index, 16) if args.index else table_addr + len(targets) * 4
    index_count = args.index_count
    if index_count <= 0:
        # Auto: read while bytes stay valid target indices; stop at alignment
        # padding (0xCC) or an out-of-range index. Cap generously — the case
        # *selector* range can be much larger than the target count.
        raw_limit = 512
        index_bytes: list[int] = []
        for i in range(raw_limit):
            b = _read_bytes(mem, af, index_addr + i, 1)[0]
            if b >= len(targets):
                break
            index_bytes.append(b)
    else:
        index_bytes = list(_read_bytes(mem, af, index_addr, index_count))

    if index_bytes:
        print(f"index-byte table 0x{index_addr:08x}: {len(index_bytes)} cases (case -> target[i])")
        line = ", ".join(f"{case}:{tgt}" for case, tgt in enumerate(index_bytes))
        print(f"  {line}")
    else:
        print("no index-byte table detected (one-level switch, case == target index)")
    return 0


def main() -> int:
    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return run(program, sys.argv[1:])
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
