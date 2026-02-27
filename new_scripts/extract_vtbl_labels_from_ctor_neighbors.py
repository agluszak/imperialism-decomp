#!/usr/bin/env python3
"""
Infer missing g_vtblT* labels from getter-adjacent constructor patterns.

Heuristic:
1) Find class getter stubs: MOV EAX,<desc>; RET (6-byte)
2) Resolve type name from class descriptor
3) Inspect immediate next function (often constructor)
4) If decompile text contains vtable literal assignment PTR_LAB_00xxxxxx,
   create label g_vtbl<type_name> at that address when missing.

Usage:
  .venv/bin/python new_scripts/extract_vtbl_labels_from_ctor_neighbors.py [--apply]
"""

from __future__ import annotations

import argparse
import re
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


def find_getter_rows(program):
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    listing = program.getListing()
    mem = program.getMemory()

    rows = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        ins1 = listing.getInstructionAt(f.getEntryPoint())
        ins2 = listing.getInstructionAt(f.getEntryPoint().add(5))
        if ins1 is None or ins2 is None:
            continue
        if f.getBody().getNumAddresses() != 6:
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

        rows.append((f, tname))
    return rows


def build_function_order_map(program):
    fm = program.getFunctionManager()
    funcs = []
    it = fm.getFunctions(True)
    while it.hasNext():
        funcs.append(it.next())
    by_ep = {int(str(f.getEntryPoint()), 16): i for i, f in enumerate(funcs)}
    return funcs, by_ep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write labels")
    ap.add_argument(
        "--allow-shared-vtbl",
        action="store_true",
        help="Allow creating labels for addresses inferred by multiple type candidates",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()

        ifc = DecompInterface()
        ifc.openProgram(program)

        candidates = []
        funcs, by_ep = build_function_order_map(program)
        for getter, tname in find_getter_rows(program):
            g_ep = int(str(getter.getEntryPoint()), 16)
            idx = by_ep.get(g_ep)
            if idx is None or idx + 1 >= len(funcs):
                continue
            ctor = funcs[idx + 1]
            if ctor is None:
                continue
            cres = ifc.decompileFunction(ctor, 25, None)
            if not cres.decompileCompleted():
                continue
            code = str(cres.getDecompiledFunction().getC())
            hits = VTBL_RE.findall(code)
            if not hits:
                continue
            vtbl_addr = int("00" + hits[-1], 16)
            label = f"g_vtbl{tname}"
            addr = af.getAddress(f"0x{vtbl_addr:08x}")
            syms = list(st.getSymbols(addr))
            has_target = any(s.getName() == label for s in syms)
            has_any_vtbl = any(s.getName().startswith("g_vtblT") for s in syms)
            candidates.append(
                (
                    tname,
                    str(getter.getEntryPoint()),
                    getter.getName(),
                    str(ctor.getEntryPoint()),
                    ctor.getName(),
                    f"0x{vtbl_addr:08x}",
                    label,
                    has_target,
                    has_any_vtbl,
                )
            )

        from collections import Counter

        vaddr_counts = Counter(c[5] for c in candidates)
        shared = [va for va, n in vaddr_counts.items() if n > 1]
        print(f"[candidates] {len(candidates)} unique_vtbl_addrs={len(vaddr_counts)} shared_vtbl_addrs={len(shared)}")
        for c in candidates[:200]:
            (
                tname,
                gaddr,
                gname,
                caddr,
                cname,
                vaddr,
                label,
                has_target,
                has_any_vtbl,
            ) = c
            print(
                f"{tname},{gaddr},{gname},ctor={caddr}:{cname},vtbl={vaddr},"
                f"shared={vaddr_counts[vaddr]},has_target={int(has_target)},has_any_vtbl={int(has_any_vtbl)}"
            )
        if len(candidates) > 200:
            print(f"... ({len(candidates) - 200} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write labels")
            return 0

        tx = program.startTransaction("Extract vtbl labels from ctor neighbors")
        ok = skip = fail = 0
        try:
            for (
                _tname,
                _gaddr,
                _gname,
                _caddr,
                _cname,
                vaddr,
                label,
                has_target,
                has_any_vtbl,
            ) in candidates:
                if has_target:
                    skip += 1
                    continue
                if (not args.allow_shared_vtbl) and vaddr_counts[vaddr] > 1:
                    skip += 1
                    continue
                addr = af.getAddress(vaddr)
                syms_now = list(st.getSymbols(addr))
                has_other_canonical = any(
                    s.getName().startswith("g_vtblT") and s.getName() != label
                    for s in syms_now
                )
                if has_other_canonical and (not args.allow_shared_vtbl):
                    skip += 1
                    continue
                try:
                    sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    sym.setPrimary()
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {vaddr} {label} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("extract vtbl labels from ctor neighbors", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
