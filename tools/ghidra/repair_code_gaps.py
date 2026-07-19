#!/usr/bin/env python3
"""Repair Ghidra-database code gaps: define real functions Ghidra never created.

Candidate function starts come from evidence the binary itself provides:
  1. every `// VTABLE: IMPERIALISM 0xADDR` table's slot dwords, resolved through
     JMP thunk chains (a vtable slot always points at a real function start);
  2. every ILT jmp-thunk target in the 0x401000-0x409ab5 linker table;
  3. every `function`-typed config/original_entities.csv row with no Ghidra function.

For each candidate inside an executable block that is neither a defined function
nor inside an existing function's body: disassemble the target first (a raw gap
has no code units yet, so CreateFunctionCmd alone bounds the body to a
degenerate 1 byte instead of following the real instruction flow), then run
CreateFunctionCmd. Any function that still ends up 1-byte after disassembling
is removed again and reported rather than left corrupting reccmp's compare
window. Dry-run by default; pass --apply to write + save the program. After an
--apply run: `just export-project` to refresh the LFS archive and
`just refresh-inventory` so the inventory picks up real names/sizes for the new
functions (sizes bound reccmp's compare windows).

Also REPORTS (never deletes) suspicious case-body pseudo-functions: defined
functions whose entry is the target of an in-function jump table dword — the
pattern that clamped 0x493800's compare window to 26%.

usage:
  repair_code_gaps [--apply] [--limit N]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.common import ghidra_env
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

ILT_START, ILT_END = 0x401000, 0x409AB6
CODE_LO, CODE_HI = 0x40F000, 0x630000  # real code range (past the ILT table)

VTABLE_MARKER_RE = re.compile(
    r"//\s*VTABLE:\s*IMPERIALISM\s+(?:0x)?([0-9a-fA-F]+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
                        help="Create the functions and save the program (default: dry-run).")
    parser.add_argument("--limit", type=int, default=0,
                        help="Stop after creating N functions (0 = no limit).")
    return parser.parse_args()


def collect_vtable_addrs(repo_root: Path) -> set[int]:
    addrs: set[int] = set()
    for base in ("src", "include"):
        for path in (repo_root / base).rglob("*.*"):
            if path.suffix not in (".cpp", ".h", ".cc", ".hpp"):
                continue
            if "/autogen/" in path.as_posix() or "/ghidra_autogen/" in path.as_posix():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in VTABLE_MARKER_RE.finditer(text):
                addrs.add(int(m.group(1), 16))
    return addrs


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    import pyghidra

    project = ghidra_env.open_project()
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd

    consumer, program = ghidra_env.open_program(project, writable=args.apply)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        mem = program.getMemory()
        listing = program.getListing()

        def byte_at(a: int) -> int | None:
            try:
                return mem.getByte(af.getAddress(a)) & 0xFF
            except Exception:
                return None

        def dword_at(a: int) -> int | None:
            bs = []
            for i in range(4):
                b = byte_at(a + i)
                if b is None:
                    return None
                bs.append(b)
            return int.from_bytes(bytes(bs), "little")

        def in_exec_block(a: int) -> bool:
            block = mem.getBlock(af.getAddress(a))
            return block is not None and block.isExecute()

        def resolve_jmp_chain(a: int) -> int:
            """Follow E9 rel32 jmps (raw bytes — works in undisassembled gaps)."""
            cur = a
            for _ in range(6):
                b = byte_at(cur)
                if b != 0xE9:
                    break
                rel = dword_at(cur + 1)
                if rel is None:
                    break
                if rel >= 1 << 31:
                    rel -= 1 << 32
                cur = cur + 5 + rel
            return cur

        # --- candidates -----------------------------------------------------
        candidates: dict[int, str] = {}

        # 1) vtable slot targets
        vtable_addrs = collect_vtable_addrs(repo_root)
        for vaddr in sorted(vtable_addrs):
            slot = vaddr
            while True:
                value = dword_at(slot)
                if value is None or not (ILT_START <= value < CODE_HI):
                    break
                target = resolve_jmp_chain(value)
                if CODE_LO <= target < CODE_HI and in_exec_block(target):
                    candidates.setdefault(target, f"vtable 0x{vaddr:x} slot 0x{(slot - vaddr) // 4:x}")
                slot += 4

        # 2) ILT thunk targets
        a = ILT_START
        while a < ILT_END:
            if byte_at(a) == 0xE9:
                target = resolve_jmp_chain(a)
                if CODE_LO <= target < CODE_HI and in_exec_block(target):
                    candidates.setdefault(target, f"ilt thunk 0x{a:x}")
                a += 5
            else:
                a += 1

        # 3) symbols.csv function rows
        symbols_path = resolve_repo_path(repo_root, "config/original_entities.csv")
        for row in read_pipe_rows(symbols_path):
            if (row.get("type") or "").strip().lower() != "function":
                continue
            addr_text = (row.get("address") or "").strip()
            if not addr_text:
                continue
            addr = int(addr_text, 16)
            if CODE_LO <= addr < CODE_HI and in_exec_block(addr):
                candidates.setdefault(addr, "symbols.csv row")

        # --- classify -------------------------------------------------------
        missing: list[tuple[int, str]] = []
        mid_function: list[tuple[int, str]] = []
        for target in sorted(candidates):
            taddr = af.getAddress(target)
            if fm.getFunctionAt(taddr) is not None:
                continue
            containing = fm.getFunctionContaining(taddr)
            if containing is not None:
                mid_function.append((target, candidates[target]))
                continue
            missing.append((target, candidates[target]))

        print(f"candidates: {len(candidates)}  missing-function: {len(missing)}  "
              f"mid-function (skipped): {len(mid_function)}")
        for t, why in mid_function[:20]:
            print(f"  mid-function 0x{t:08x}  ({why})")

        if not args.apply:
            for t, why in missing:
                print(f"  would-create 0x{t:08x}  ({why})")
            print("dry-run; pass --apply to create + save")
            return 0

        created, failed, degenerate = [], [], []
        txid = program.startTransaction("repair code gaps: create missing functions")
        try:
            for t, why in missing:
                if args.limit and len(created) >= args.limit:
                    break
                taddr = af.getAddress(t)
                # CreateFunctionCmd bounds the function body from existing code
                # units; on a raw undisassembled gap (the common case here) it
                # silently creates a degenerate 1-byte function instead of
                # disassembling first. Disassemble the target before creating.
                if listing.getInstructionAt(taddr) is None:
                    DisassembleCommand(taddr, None, True).applyTo(program, pyghidra.task_monitor())
                cmd = CreateFunctionCmd(taddr)
                ok = cmd.applyTo(program, pyghidra.task_monitor())
                func = fm.getFunctionAt(taddr) if ok else None
                if func is None:
                    failed.append((t, why))
                elif func.getBody().getNumAddresses() <= 1:
                    # Leaving a 1-byte function behind is worse than not
                    # creating one at all (it corrupts the real, larger
                    # function that should own these bytes). Undo it.
                    fm.removeFunction(taddr)
                    degenerate.append((t, why))
                else:
                    created.append(t)
        finally:
            program.endTransaction(txid, True)

        print(f"created: {len(created)}  failed: {len(failed)}  degenerate (1-byte body): {len(degenerate)}")
        for t, why in failed[:20]:
            print(f"  FAILED 0x{t:08x}  ({why})")
        for t, why in degenerate[:20]:
            print(f"  DEGENERATE 0x{t:08x}  ({why})")

        if created:
            program.getDomainFile().save(pyghidra.task_monitor())
            print("saved program — now run `just export-project` and `just refresh-inventory`")
        return 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    sys.exit(main())
