#!/usr/bin/env python3
"""
Add g_vtblT* alias labels for classes that share the same inferred vtable address.

This complements extract_vtbl_labels_from_ctor_neighbors.py by handling shared-vtable
cases conservatively as additional alias labels (non-destructive).

Heuristic:
1) Find getter stubs: MOV EAX,<desc>; RET (6-byte)
2) Resolve type name from class descriptor
3) Inspect adjacent constructor candidate (next function) and infer vtable literal
4) Group by inferred vtable address
5) For addresses used by multiple classes, add g_vtbl<type> labels for each class

Usage:
  .venv/bin/python new_scripts/add_shared_vtbl_alias_labels.py
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
VTBL_RE = re.compile(r"PTR_LAB_00([0-9a-fA-F]{6})")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def read_ascii_z(mem, addr, max_len=128):
    chars = []
    for i in range(max_len):
        try:
            b = mem.getByte(addr.add(i)) & 0xFF
        except Exception:
            return None
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return None
        chars.append(chr(b))
    if not chars:
        return None
    return "".join(chars)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()
        st = program.getSymbolTable()

        funcs = []
        it = fm.getFunctions(True)
        while it.hasNext():
            funcs.append(it.next())
        by_ep = {int(str(f.getEntryPoint()), 16): i for i, f in enumerate(funcs)}

        ifc = DecompInterface()
        ifc.openProgram(program)

        pairs: list[tuple[str, str]] = []  # (type_name, vtbl_addr_hex)
        for getter in funcs:
            ins1 = listing.getInstructionAt(getter.getEntryPoint())
            ins2 = listing.getInstructionAt(getter.getEntryPoint().add(5))
            if ins1 is None or ins2 is None:
                continue
            if getter.getBody().getNumAddresses() != 6:
                continue
            s1 = str(ins1)
            if not s1.startswith("MOV EAX,0x") or str(ins2) != "RET":
                continue

            try:
                desc = int(s1.split("0x", 1)[1], 16)
                tname_addr = mem.getInt(af.getAddress(f"0x{desc:08x}")) & 0xFFFFFFFF
            except Exception:
                continue

            tname = read_ascii_z(mem, af.getAddress(f"0x{tname_addr:08x}"))
            if not tname or not tname.startswith("T"):
                continue

            idx = by_ep.get(int(str(getter.getEntryPoint()), 16))
            if idx is None or idx + 1 >= len(funcs):
                continue
            ctor = funcs[idx + 1]
            cres = ifc.decompileFunction(ctor, 25, None)
            if not cres.decompileCompleted():
                continue
            code = str(cres.getDecompiledFunction().getC())
            hits = VTBL_RE.findall(code)
            if not hits:
                continue
            vtbl_addr = f"0x00{hits[-1].lower()}"
            pairs.append((tname, vtbl_addr))

        cnt = Counter(v for _, v in pairs)
        shared_groups = defaultdict(set)
        for tname, vaddr in pairs:
            if cnt[vaddr] > 1:
                shared_groups[vaddr].add(tname)

        print(f"[shared_groups] {len(shared_groups)}")
        for vaddr, types in sorted(shared_groups.items()):
            print(f"  {vaddr}: {', '.join(sorted(types))}")

        tx = program.startTransaction("Add shared vtbl alias labels")
        ok = skip = fail = 0
        try:
            for vaddr, types in shared_groups.items():
                addr = af.getAddress(vaddr)
                existing = {s.getName() for s in st.getSymbols(addr)}
                for tname in sorted(types):
                    label = f"g_vtbl{tname}"
                    if label in existing:
                        skip += 1
                        continue
                    try:
                        st.createLabel(addr, label, SourceType.USER_DEFINED)
                        ok += 1
                    except Exception as ex:
                        fail += 1
                        print(f"[fail] {vaddr} {label} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("add shared vtbl alias labels", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
