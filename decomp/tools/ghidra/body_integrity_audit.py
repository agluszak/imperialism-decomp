#!/usr/bin/env python3
"""Read-only: audit Ghidra function-body integrity against the curated inventory.

Detects the defect classes that slipped past the symbol-integrity gate before
(bd 6q2 / b69m):

  - multi-range bodies: a function whose body has holes where demoted inner
    functions were never reassigned (punctured body). Gaps are classified by
    content: unowned instructions or undefined bytes are defects; embedded
    data (inline jump tables), alignment padding, and bytes owned by a
    neighboring body are reported separately as benign multi-range layout
  - nested entry points: a function whose body contains another function's
    entry point (over-broad body swallowing a real function)
  - curated size drift: config/original_entities.csv size column disagreeing
    with the DB body byte count (the merge takes the larger for embedded
    owners; a smaller DB number means the export went stale or the repair was
    never applied)
  - unowned reachable code: instructions inside a curated function's recorded
    extent that belong to no DB function body

usage: body-integrity-audit [--limit N]
"""

from __future__ import annotations

import bisect
import csv
import sys

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__)
INVENTORY = REPO_ROOT / "config" / "original_entities.csv"


def curated_functions() -> dict[int, tuple[int, str]]:
    """address -> (size, name) for every curated sized function row."""
    rows = {}
    with INVENTORY.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="|"):
            if (row.get("type") or "").strip() != "function":
                continue
            size = (row.get("size") or "").strip()
            address = (row.get("address") or "").strip()
            if not size.isdigit() or not address:
                continue
            rows[int(address, 16)] = (int(size), (row.get("name") or "").strip())
    return rows


def body_ranges(func) -> list[tuple[int, int]]:
    ranges = [
        (r.getMinAddress().getOffset(), r.getMaxAddress().getOffset())
        for r in func.getBody().getAddressRanges()
    ]
    ranges.sort()
    return ranges


def main() -> int:
    limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 25

    project = ghidra_env.open_project()
    consumer, program = ghidra_env.open_program(project)
    try:
        fm = program.getFunctionManager()
        curated = curated_functions()

        hole_rows = []
        nested_rows = []
        size_rows = []
        unowned_rows = []

        # Map every DB function entry for the containment test.
        entries = sorted(
            (f.getEntryPoint().getOffset(), f.getBody().getNumAddresses(), f.getName())
            for f in fm.getFunctions(True)
        )
        entry_addrs = {e[0] for e in entries}
        sorted_entries = [e[0] for e in entries]
        entry_names = {e[0]: e[2] for e in entries}

        listing = program.getListing()
        space = program.getAddressFactory().getDefaultAddressSpace()
        embedded_rows = []

        def classify_gap(lo: int, hi: int) -> str:
            """Content of an inter-range gap inside a function body.

            - 'owned': every byte belongs to another function body (shared tail)
            - 'embedded-data': only data units / padding between code ranges —
              VC5 emits inline jump tables (memmove/_memcpy Duff dispatch) and
              alignment inside functions; legitimate multi-range bodies
            - 'undef': bytes never turned into code or data
            - 'insns': unowned instructions — a real puncture (EH/funcinfo or
              switch-dispatch code the analyzer could not reach)
            """
            has_insn = has_undef = has_other = False
            a = space.getAddress(lo)
            while a.getOffset() <= hi:
                cu = listing.getCodeUnitAt(a)
                if cu is None:
                    has_undef = True
                    a = a.next()
                    continue
                kind = cu.getClass().getSimpleName()
                if kind == "InstructionDB":
                    mnemonic = str(cu)
                    if fm.getFunctionContaining(cu.getAddress()) is not None:
                        has_other = True
                    elif mnemonic in ("NOP", "INT3") or mnemonic.startswith("MOV EAX,EAX"):
                        pass  # inter-case alignment padding
                    else:
                        has_insn = True
                elif kind != "DataDB":
                    has_undef = True
                a = cu.getMaxAddress().next()
            if has_insn:
                return "insns"
            if has_undef:
                return "undef"
            if has_other:
                return "owned"
            return "embedded-data"

        for entry, _size, name in entries:
            func = fm.getFunctionAt(space.getAddress(entry))
            ranges = body_ranges(func)
            if len(ranges) > 1:
                holes = [
                    (ranges[i][1] + 1, ranges[i + 1][0] - 1)
                    for i in range(len(ranges) - 1)
                ]
                bad = []
                benign = []
                for lo, hi in holes:
                    kind = classify_gap(lo, hi)
                    (bad if kind in ("insns", "undef") else benign).append((lo, hi, kind))
                if bad:
                    hole_rows.append((entry, name, sum(b - a + 1 for a, b in ranges), bad))
                if benign:
                    embedded_rows.append((entry, name, benign))
            # Nested entry: another function's entry inside an actual body
            # range — an entry sitting in an inter-range gap is a neighboring
            # thunk/shared tail, not a swallowed function.
            for lo, hi in ranges:
                idx = bisect.bisect_right(sorted_entries, lo)
                while idx < len(sorted_entries) and sorted_entries[idx] <= hi:
                    e2 = sorted_entries[idx]
                    if e2 != entry:
                        nested_rows.append((entry, name, e2, entry_names[e2]))
                    idx += 1

        # Curated size vs DB size. The curated number is the export's
        # instruction-byte count (SyncExports_Ghidra.func_insn_bytes), not the
        # body address count — bodies also cover embedded data and padding.
        # A row disagrees only when it matches neither metric.
        for addr, (csize, cname) in curated.items():
            func = fm.getFunctionAt(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(addr)
            )
            if func is None:
                continue
            dbsize = func.getBody().getNumAddresses()
            insns = listing.getInstructions(func.getBody(), True)
            isize = sum(i.getLength() for i in insns)
            if csize != dbsize and csize != isize:
                size_rows.append((addr, cname or func.getName(), csize, dbsize))

        # Instructions inside a curated extent owned by no body.
        for addr, (csize, cname) in sorted(curated.items()):
            if csize < 8:
                continue
            cursor = listing.getInstructionAt(space.getAddress(addr))
            while cursor is not None:
                off = cursor.getAddress().getOffset()
                if off >= addr + csize:
                    break
                owner = fm.getFunctionContaining(cursor.getAddress())
                mnemonic = str(cursor)
                if (
                    owner is None
                    and off not in entry_addrs
                    and mnemonic not in ("NOP", "INT3")
                    and not mnemonic.startswith("MOV EAX,EAX")
                ):
                    unowned_rows.append((addr, cname, off, mnemonic))
                cursor = cursor.getNext()

        print(f"DB functions: {len(entries)}; curated sized rows: {len(curated)}")
        print(f"bodies with unowned-code holes: {len(hole_rows)}")
        print(f"bodies with benign embedded-data/owned gaps: {len(embedded_rows)}")
        print(f"bodies containing another entry point: {len(nested_rows)}")
        print(f"curated/DB size disagreements: {len(size_rows)}")
        print(f"unowned instructions inside curated extents: {len(unowned_rows)}\n")

        for addr, name, total, holes in hole_rows[:limit]:
            print(f"0x{addr:08x} {name} ({total}B body)")
            for lo, hi, kind in holes:
                print(f"    hole[{kind}] 0x{lo:08x}-0x{hi:08x}")
        for addr, name, gaps in embedded_rows[:limit]:
            print(f"0x{addr:08x} {name} embedded gaps:", ", ".join(f"{k}:{lo:08x}-{hi:08x}" for lo, hi, k in gaps))
        for addr, name, e2, n2 in nested_rows[:limit]:
            print(f"0x{addr:08x} {name} contains entry 0x{e2:08x} ({n2})")
        for addr, name, csize, dbsize in size_rows[:limit]:
            print(f"0x{addr:08x} {name}: curated {csize} vs DB {dbsize}")
        for addr, name, off, insn in unowned_rows[:limit]:
            print(f"0x{addr:08x} {name}: unowned insn at 0x{off:08x}: {insn}")

        return 1 if (hole_rows or nested_rows or size_rows or unowned_rows) else 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    sys.exit(main())
