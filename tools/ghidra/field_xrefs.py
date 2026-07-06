#!/usr/bin/env python3
"""Which member functions of a class read/write a given `this`-relative offset?

Address-based `xrefs` answers "who references this address"; class-layout work
needs the other axis: "who touches field +0xNN of TCity". This scans the bodies
of every function attributed to the class (symbols.csv names `Class::...` +
config/function_ownership.csv rows owned by src/game/<Class>.cpp), tracking
which registers hold `this` (starts in ECX, follows plain `MOV reg, thisreg`
copies, drops on any other write / call clobber), and reports instructions that
access `[thisreg + offset]`.

Lead generator, not proof: it misses `this` reloaded from memory/stack spills,
accesses made through base/derived methods not attributed to the class, and
inlined helpers. An empty result does not mean the field is unused.

usage: field-xrefs <Class> [0xOFF] [--limit N]
  with 0xOFF  — every access of that offset: function, address, R/W, instruction
  without     — histogram of all this-relative offsets touched by the class
"""

from __future__ import annotations

import re
import sys

from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file
from tools.common.symbols import names_by_address

MEM_RE = re.compile(r"\[(E[A-Z]{2})(?:\s*\+\s*(0x[0-9a-fA-F]+))?\]")
MOV_REG_REG_RE = re.compile(r"^MOV (E[A-Z]{2}),(E[A-Z]{2})$")
DEST_REG_RE = re.compile(r"^[A-Z.]+ (E[A-Z]{2})[,]?")
CALL_CLOBBERS = ("EAX", "ECX", "EDX")


def class_function_addrs(repo_root, cls: str) -> dict[int, str]:
    """address -> name for every function attributed to the class."""
    names_by_addr = names_by_address(repo_root)
    out: dict[int, str] = {
        addr: name
        for addr, name in names_by_addr.items()
        if name.startswith(f"{cls}::") or name.startswith(f"thunk_{cls}::")
    }
    target_cpp = f"src/game/{cls}.cpp"
    for row in read_pipe_rows(repo_root / "config" / "function_ownership.csv"):
        if row.get("target_cpp") == target_cpp:
            try:
                addr = int(row["address"], 16)
            except ValueError:
                continue
            out.setdefault(addr, names_by_addr.get(addr, "?"))
    return out


def this_accesses(program, fn) -> list[tuple[int, str, str, str]]:
    """(address, offset_hex, R/W, instruction_text) for this-relative accesses."""
    listing = program.getListing()
    tainted = {"ECX"}
    hits: list[tuple[int, str, str, str]] = []
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        # Ghidra text keeps registers/mnemonics uppercase and hex lowercase
        # ("MOV dword ptr [ECX + 0x4],ESI") — do NOT .upper() it, that would
        # break the 0x offset match.
        text = str(ins)
        mnemonic = ins.getMnemonicString().upper()

        for m in MEM_RE.finditer(text):
            reg, off = m.group(1), m.group(2) or "0x0"
            if reg not in tainted:
                continue
            first_operand = text.split(",")[0]
            rw = "W" if m.start() < len(first_operand) and mnemonic not in ("CMP", "TEST", "PUSH") else "R"
            hits.append((int(str(ins.getAddress()), 16), off.lower(), rw, str(ins)))

        # Taint bookkeeping AFTER recording (an access uses pre-write values).
        copy = MOV_REG_REG_RE.match(text)
        if copy:
            dst, src = copy.group(1), copy.group(2)
            if src in tainted:
                tainted.add(dst)
            else:
                tainted.discard(dst)
            continue
        if mnemonic == "CALL":
            for reg in CALL_CLOBBERS:
                tainted.discard(reg)
            continue
        dest = DEST_REG_RE.match(text)
        if dest and mnemonic not in ("CMP", "TEST", "PUSH"):
            tainted.discard(dest.group(1))
    return hits


def run(program, argv: list[str]) -> int:
    positional: list[str] = []
    limit = 200
    i = 0
    while i < len(argv):
        if argv[i] == "--limit" and i + 1 < len(argv):
            limit = int(argv[i + 1])
            i += 2
            continue
        if not argv[i].startswith("-"):
            positional.append(argv[i])
        i += 1
    if not positional:
        print("usage: field-xrefs <Class> [0xOFF] [--limit N]", file=sys.stderr)
        return 2
    cls = positional[0]
    want_off = positional[1].lower() if len(positional) > 1 else None

    repo_root = repo_root_from_file(__file__)
    members = class_function_addrs(repo_root, cls)
    if not members:
        print(f"no functions attributed to class {cls!r} (symbols.csv / ownership)", file=sys.stderr)
        return 1

    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    per_offset: dict[str, list[tuple[int, str, str, str, str]]] = {}
    for addr in sorted(members):
        fn = fm.getFunctionContaining(af.getAddress(addr))
        if fn is None:
            continue
        for ins_addr, off, rw, text in this_accesses(program, fn):
            per_offset.setdefault(off, []).append((ins_addr, rw, members[addr], f"0x{addr:08x}", text))

    if want_off is None:
        print(f"class {cls}: {len(members)} attributed functions, "
              f"{sum(len(v) for v in per_offset.values())} this-relative accesses")
        print("offset|reads|writes|functions|sample")
        for off in sorted(per_offset, key=lambda o: int(o, 16)):
            rows = per_offset[off]
            fns = sorted({r[2] for r in rows})
            sample = rows[0][4]
            print(f"{off}|{sum(1 for r in rows if r[1] == 'R')}|"
                  f"{sum(1 for r in rows if r[1] == 'W')}|{len(fns)}|{sample}")
        return 0

    rows = per_offset.get(want_off, [])
    print(f"class {cls} field {want_off}: {len(rows)} accesses")
    print("insn_addr|rw|function|fn_addr|instruction")
    for ins_addr, rw, name, fn_addr, text in rows[:limit]:
        print(f"0x{ins_addr:08x}|{rw}|{name}|{fn_addr}|{text}")
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more (raise --limit)")
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
