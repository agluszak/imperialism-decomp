#!/usr/bin/env python3
"""Define a computed-jump switch table in the Ghidra DB so body fixup can follow it.

Some giant dispatchers use `JMP dword ptr [reg*4 + table]` where Ghidra's analysis
never recovered the jump table, so the case bodies stay outside the function body
(CreateFunctionCmd.fixupFunctionBody follows flow through *references*, and a
computed jump with no references is a flow dead end). This tool:

  1. reads `count` dwords at `table` and validates every target lands in an
     executable block;
  2. types the table as dwords (and an optional trailing byte index table as
     bytes) so later disassembly cannot eat it as code;
  3. adds COMPUTED_JUMP references from the jump instruction to each unique
     target and disassembles the targets.

After an --apply run, re-run `fix_function_bounds <dispatcher> --force --apply`
so the enclosing function reabsorbs the case bodies, then `just export-project`
and `just refresh-inventory`.

usage:
  create_switch_table 0xJUMPADDR 0xTABLE COUNT [--index-table 0xADDR LEN] [--apply]
"""

from __future__ import annotations

import argparse

from tools.common import ghidra_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("jump", help="Address of the JMP dword ptr [..] instruction (0x...).")
    parser.add_argument("table", help="Address of the jump table (0x...).")
    parser.add_argument("count", type=lambda v: int(v, 0), help="Number of dword entries.")
    parser.add_argument("--index-table", nargs=2, metavar=("ADDR", "LEN"), default=None,
                        help="Optional byte index table: address and byte length.")
    parser.add_argument("--apply", action="store_true",
                        help="Write references/data and save the program (default: dry-run).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    jump = int(args.jump, 16)
    table = int(args.table, 16)

    import pyghidra

    project = ghidra_env.open_project()
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.program.model.data import ByteDataType, DWordDataType
    from ghidra.program.model.symbol import RefType, SourceType

    consumer, program = ghidra_env.open_program(project, writable=args.apply)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        listing = program.getListing()
        refman = program.getReferenceManager()

        def dword_at(a: int) -> int:
            bs = bytes((mem.getByte(af.getAddress(a + i)) & 0xFF) for i in range(4))
            return int.from_bytes(bs, "little")

        def in_exec_block(a: int) -> bool:
            block = mem.getBlock(af.getAddress(a))
            return block is not None and block.isExecute()

        jump_addr = af.getAddress(jump)
        insn = listing.getInstructionAt(jump_addr)
        if insn is None:
            print(f"ERROR: no instruction at 0x{jump:08x} (disassemble it first)")
            return 1
        if not insn.getFlowType().isComputed():
            print(f"ERROR: instruction at 0x{jump:08x} is not a computed jump: {insn}")
            return 1

        targets = [dword_at(table + 4 * i) for i in range(args.count)]
        bad = [t for t in targets if not in_exec_block(t)]
        if bad:
            print("ERROR: non-executable targets: " + ", ".join(f"0x{t:08x}" for t in bad))
            return 1

        existing = {r.getToAddress().getOffset() for r in refman.getReferencesFrom(jump_addr)}
        missing = [t for t in dict.fromkeys(targets) if t not in existing]
        print(f"jump 0x{jump:08x}  table 0x{table:08x}  entries {args.count}")
        for i, t in enumerate(targets):
            mark = "" if t not in missing else "  (new ref)"
            print(f"  case[{i:2}] -> 0x{t:08x}{mark}")

        if not args.apply:
            print("dry-run; pass --apply to write references + data and save")
            return 0

        txid = program.startTransaction(f"create switch table 0x{table:x} for jump 0x{jump:x}")
        try:
            listing.clearCodeUnits(af.getAddress(table),
                                   af.getAddress(table + 4 * args.count - 1), False)
            for i in range(args.count):
                listing.createData(af.getAddress(table + 4 * i), DWordDataType.dataType)
            if args.index_table:
                idx_addr, idx_len = int(args.index_table[0], 16), int(args.index_table[1], 0)
                listing.clearCodeUnits(af.getAddress(idx_addr),
                                       af.getAddress(idx_addr + idx_len - 1), False)
                for i in range(idx_len):
                    listing.createData(af.getAddress(idx_addr + i), ByteDataType.dataType)
            for t in missing:
                refman.addMemoryReference(jump_addr, af.getAddress(t),
                                          RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0)
            for t in dict.fromkeys(targets):
                taddr = af.getAddress(t)
                if listing.getInstructionAt(taddr) is None:
                    DisassembleCommand(taddr, None, True).applyTo(program, pyghidra.task_monitor())
        finally:
            program.endTransaction(txid, True)

        program.getDomainFile().save(pyghidra.task_monitor())
        print(f"added {len(missing)} references; saved program — now re-run "
              f"fix_function_bounds on the dispatcher, then `just export-project` "
              f"and `just refresh-inventory`")
        return 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
