#!/usr/bin/env python3
"""Read-only: read memory at an address as a typed value.

Fills the gap where you need the *value* of a data constant (a float scale, a jump-table
entry, a vtable slot pointer, a string) without hacking vtable_dump or hand-unpacking bytes.

usage:
  read_data 0xADDR [type] [count]

types: byte word dword qword float double ptr str bytes   (default: dword)
`count` reads that many consecutive elements (default 1); for `bytes` it is the byte length
(default 16); for `str` it is the max length scanned (default 256).

examples:
  read_data 0x006598d8 double        # 11733.857334728455  (the sea-segment angle scale)
  read_data 0x0065999c ptr 2         # two vtable slot pointers
  read_data 0x00697450 dword 6       # a 6-entry int table
  read_data 0x006970a0 str
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env

_STRIDES = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "float": 4, "double": 8, "ptr": 4}


def _read_one(mem, java, addr, typ: str) -> str:
    if typ == "byte":
        v = mem.getByte(addr) & 0xFF
        return f"0x{v:02x} ({v}, {v if v < 128 else v - 256} signed)"
    if typ == "word":
        v = mem.getShort(addr) & 0xFFFF
        return f"0x{v:04x} ({v}, {v if v < 0x8000 else v - 0x10000} signed)"
    if typ in ("dword", "ptr"):
        v = mem.getInt(addr) & 0xFFFFFFFF
        if typ == "ptr":
            return f"0x{v:08x}"
        return f"0x{v:08x} ({v}, {v if v < 0x80000000 else v - 0x100000000} signed)"
    if typ == "qword":
        v = mem.getLong(addr) & 0xFFFFFFFFFFFFFFFF
        return f"0x{v:016x} ({v})"
    if typ == "float":
        return f"{java['Float'].intBitsToFloat(mem.getInt(addr))!r}"
    if typ == "double":
        return f"{java['Double'].longBitsToDouble(mem.getLong(addr))!r}"
    raise ValueError(f"unknown type: {typ}")


def _read_string(mem, af, addr_int: int, maxlen: int) -> str:
    out = bytearray()
    for i in range(maxlen):
        b = mem.getByte(af.getAddress(addr_int + i)) & 0xFF
        if b == 0:
            break
        out.append(b)
    return repr(out.decode("latin-1"))


def _read_bytes(mem, af, addr_int: int, length: int) -> str:
    row = []
    for i in range(length):
        row.append(f"{mem.getByte(af.getAddress(addr_int + i)) & 0xFF:02x}")
    return " ".join(row)


def run(program, argv: list[str]) -> int:
    if not argv:
        print("usage: read-data 0xADDR [byte|word|dword|qword|float|double|ptr|str|bytes] [count]",
              file=sys.stderr)
        return 2
    addr_int = int(argv[0], 16)
    typ = (argv[1] if len(argv) > 1 else "dword").lower()
    count = int(argv[2], 0) if len(argv) > 2 else None

    from java.lang import Double as JDouble
    from java.lang import Float as JFloat

    java = {"Float": JFloat, "Double": JDouble}
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()

    try:
        if typ == "str":
            print(f"0x{addr_int:08x} str  {_read_string(mem, af, addr_int, count or 256)}")
            return 0
        if typ == "bytes":
            print(f"0x{addr_int:08x} bytes {_read_bytes(mem, af, addr_int, count or 16)}")
            return 0
        if typ not in _STRIDES:
            print(f"unknown type: {typ}", file=sys.stderr)
            return 2
        stride = _STRIDES[typ]
        n = count if count is not None else 1
        for i in range(n):
            a = af.getAddress(addr_int + i * stride)
            print(f"{a} {typ:6s} {_read_one(mem, java, a, typ)}")
    except Exception as exc:  # noqa: BLE001 - MemoryAccessException etc.
        print(f"error reading 0x{addr_int:08x} as {typ}: {exc}", file=sys.stderr)
        return 1
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
