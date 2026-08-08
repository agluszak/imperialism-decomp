#!/usr/bin/env python3
"""Read-only: search the whole binary for a value, in code text or raw data.

Useful for message-map/handler hunting (e.g. "does anything check for message 0x4ef
anywhere") when the value could plausibly live in either an instruction operand or a
data table (like an AFX_MSGMAP_ENTRY array) that Ghidra hasn't structured.

usage:
  search_whole_binary text 0x4ef        # substring match over every function's
                                          # disassembled instruction text
  search_whole_binary dword 0x4ef        # raw little-endian 4-byte scan over every
                                          # initialized, readable memory block
  search_whole_binary imm 0x11f8        # instructions with this exact immediate
                                          # operand value (event codes, callback
                                          # address-taken sites)
"""

from __future__ import annotations

import sys

import jpype

from tools.common import ghidra_env


def search_text(program, needle: str, limit: int) -> int:
    listing = program.getListing()
    fm = program.getFunctionManager()
    count = 0
    fn_count = 0
    for fn in fm.getFunctions(True):
        fn_count += 1
        it = listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            ins = it.next()
            s = str(ins)
            if needle in s:
                print(f"{fn.getName()} @ {fn.getEntryPoint()}: {ins.getAddress()}  {ins}")
                count += 1
                if count >= limit:
                    print("...truncated")
                    return count
    print(f"scanned {fn_count} functions, total matches: {count}")
    return count


def search_dword(program, target: int, limit: int) -> int:
    # NOTE: do NOT reimplement this with Memory.getBytes(Address, byte[]) + a Python
    # bytearray/bytes buffer or a manually-constructed jpype.JArray(JByte) pulled into
    # bulk blocks — both were tried and produced silent, confidently-wrong all-zero
    # reads in some invocation contexts (reproduced consistently under `python -m`,
    # not under direct script execution; root cause not fully pinned down, smells like
    # a jpype JVM-attach/threading quirk specific to this environment). Use Ghidra's
    # own Memory.findBytes search instead, which reads memory content-search state
    # entirely on the Java side — no Python-side byte marshalling to get wrong.
    mem = program.getMemory()
    target_bytes = target.to_bytes(4, "little")
    JByte = jpype.JArray(jpype.JByte)
    pattern = JByte(4)
    for i, b in enumerate(target_bytes):
        pattern[i] = jpype.JByte(b if b < 128 else b - 256)
    monitor = jpype.JClass("ghidra.util.task.TaskMonitor").DUMMY

    count = 0
    start_addr = mem.getMinAddress()
    end_addr = mem.getMaxAddress()
    while True:
        found = mem.findBytes(start_addr, end_addr, pattern, None, True, monitor)
        if found is None:
            break
        block = mem.getBlock(found)
        print(f"{block.getName() if block else '?'}: {found}")
        count += 1
        if count >= limit:
            print("...truncated")
            return count
        start_addr = found.add(1)
        if start_addr.compareTo(end_addr) > 0:
            break
    print(f"total: {count}")
    return count


def search_imm(program, target: int, limit: int) -> int:
    """Find instructions with `target` as an immediate/scalar operand anywhere.

    Precise variant of `text` search: matches operand *values*, not rendered
    strings, so `imm 0x11f8` finds `PUSH 0x11f8` / `CMP EAX,0x11f8` without
    also matching addresses that merely contain the digits. This is how
    "who dispatches event code X" and "who takes function Y's address as a
    callback" queries run (an address-taken function shows up as a MOV/PUSH
    immediate with zero CALL xrefs).
    """
    listing = program.getListing()
    fm = program.getFunctionManager()
    count = 0
    it = listing.getInstructions(True)
    while it.hasNext():
        ins = it.next()
        matched = False
        for op_idx in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(op_idx):
                # ghidra.program.model.scalar.Scalar exposes getUnsignedValue.
                get_unsigned = getattr(obj, "getUnsignedValue", None)
                if get_unsigned is None:
                    continue
                if int(get_unsigned()) == target:
                    matched = True
                    break
            if matched:
                break
        if not matched:
            continue
        fn = fm.getFunctionContaining(ins.getAddress())
        fname = fn.getName() if fn else "?"
        print(f"{fname}: {ins.getAddress()}  {ins}")
        count += 1
        if count >= limit:
            print("...truncated")
            return count
    print(f"total: {count}")
    return count


MODES = ("text", "dword", "imm")


def run(program, argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in MODES:
        print("usage: search text|dword|imm <value> [limit]", file=sys.stderr)
        return 2
    mode = argv[0]
    limit = int(argv[2]) if len(argv) > 2 else 200
    if mode == "text":
        search_text(program, argv[1], limit)
    elif mode == "dword":
        search_dword(program, int(argv[1], 16), limit)
    else:
        search_imm(program, int(argv[1], 16), limit)
    return 0


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] not in MODES:
        print("usage: search_whole_binary text|dword|imm <value> [limit]", file=sys.stderr)
        return 2

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
    sys.exit(main())
