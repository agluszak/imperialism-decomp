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


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] not in ("text", "dword"):
        print("usage: search_whole_binary text|dword <value> [limit]", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 200

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        if mode == "text":
            search_text(program, sys.argv[2], limit)
        else:
            search_dword(program, int(sys.argv[2], 16), limit)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
