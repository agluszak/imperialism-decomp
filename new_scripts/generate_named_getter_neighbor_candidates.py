#!/usr/bin/env python3
"""
Generate promotion candidates from already-renamed class getters:
  GetT*ClassNamePointer

The script infers adjacent create/ctor/dtor neighbors by function order and
adds only candidates that still look unresolved (FUN_* + simple heuristics).

Usage:
  .venv/bin/python new_scripts/generate_named_getter_neighbor_candidates.py [out_csv] [project_root]
  .venv/bin/python new_scripts/generate_named_getter_neighbor_candidates.py tmp_decomp/named_getter_neighbors.csv
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def first_n_instructions(listing, func, n=10):
    out = []
    it = listing.getInstructions(func.getBody(), True)
    count = 0
    while it.hasNext() and count < n:
        out.append(str(it.next()))
        count += 1
    return out


def called_function_names(listing, fm, func):
    names = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext():
        ins = it.next()
        if not str(ins).startswith("CALL "):
            continue
        refs = ins.getReferencesFrom()
        try:
            ref_iter = refs
        except Exception:
            ref_iter = []
        for ref in ref_iter:
            to = ref.getToAddress()
            callee = fm.getFunctionAt(to)
            if callee is not None:
                names.append(callee.getName())
    return names


def infer_vtable_addr_from_ctor(ifc, func):
    try:
        res = ifc.decompileFunction(func, 15, None)
        if not res.decompileCompleted():
            return None
        code = res.getDecompiledFunction().getC()
    except Exception:
        return None
    hits = re.findall(r"PTR_LAB_00([0-9a-fA-F]{6})", code)
    if not hits:
        return None
    return int("00" + hits[-1], 16)


def main() -> int:
    out_csv = (
        Path(sys.argv[1])
        if len(sys.argv) >= 2
        else Path("tmp_decomp/named_getter_neighbor_candidates.csv")
    )
    root = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    getter_re = re.compile(r"^Get(T.+)ClassNamePointer$")

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        listing = program.getListing()
        mem = program.getMemory()
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        def ep_int(func):
            return int(str(func.getEntryPoint()), 16)

        funcs = []
        it = fm.getFunctions(True)
        while it.hasNext():
            funcs.append(it.next())
        funcs.sort(key=ep_int)
        by_ep = {ep_int(func): idx for idx, func in enumerate(funcs)}

        ifc = DecompInterface()
        ifc.openProgram(program)

        rows = []
        stats = {"getters": 0, "rows": 0, "create": 0, "ctor": 0, "dtor": 0}

        for getter in funcs:
            match = getter_re.match(getter.getName())
            if not match:
                continue
            stats["getters"] += 1
            type_name = match.group(1)
            getter_ep = ep_int(getter)
            idx = by_ep[getter_ep]

            prev_f = funcs[idx - 1] if idx > 0 else None
            ctor_f = funcs[idx + 1] if idx + 1 < len(funcs) else None
            dtor_f = funcs[idx + 2] if idx + 2 < len(funcs) else None

            desc = None
            ins1 = listing.getInstructionAt(getter.getEntryPoint())
            if ins1 is not None:
                s1 = str(ins1)
                if s1.startswith("MOV EAX,0x"):
                    try:
                        desc = int(s1.split("0x", 1)[1], 16)
                    except Exception:
                        desc = None
            if desc is None:
                continue

            tname_addr = None
            try:
                tname_addr = mem.getInt(af.getAddress(f"0x{desc:08x}")) & 0xFFFFFFFF
            except Exception:
                pass

            create_addr = ""
            ctor_addr = ""
            dtor_addr = ""
            vtbl_addr = ""

            ctor_ok = False
            if ctor_f is not None and ctor_f.getName().startswith("FUN_"):
                ctor_size = ctor_f.getBody().getNumAddresses()
                first_ins = first_n_instructions(listing, ctor_f, 10)
                has_vtbl_mov = any(
                    ins.startswith("MOV dword ptr [ECX],0x00")
                    or ins.startswith("MOV dword ptr [EAX],0x00")
                    or ins.startswith("MOV dword ptr [ESI],0x00")
                    for ins in first_ins
                )
                vtbl = infer_vtable_addr_from_ctor(ifc, ctor_f)
                if ctor_size <= 220 and (has_vtbl_mov or vtbl is not None):
                    ctor_ok = True
                    ctor_addr = f"0x{ep_int(ctor_f):08x}"
                    if vtbl is not None:
                        vtbl_addr = f"0x{vtbl:08x}"
                    stats["ctor"] += 1

            if dtor_f is not None and dtor_f.getName().startswith("FUN_"):
                dtor_size = dtor_f.getBody().getNumAddresses()
                calls = called_function_names(listing, fm, dtor_f)
                has_cleanup_call = any(
                    ("FreeHeapBufferIfNotNull" in name)
                    or ("Destruct" in name)
                    or ("Release" in name)
                    for name in calls
                )
                first_ins = first_n_instructions(listing, dtor_f, 10)
                has_vtbl_mov = any(
                    ins.startswith("MOV dword ptr [ECX],0x00")
                    or ins.startswith("MOV dword ptr [EAX],0x00")
                    or ins.startswith("MOV dword ptr [ESI],0x00")
                    for ins in first_ins
                )
                if dtor_size <= 260 and (has_cleanup_call or (ctor_ok and has_vtbl_mov)):
                    dtor_addr = f"0x{ep_int(dtor_f):08x}"
                    stats["dtor"] += 1

            if prev_f is not None and prev_f.getName().startswith("FUN_"):
                create_size = prev_f.getBody().getNumAddresses()
                calls = called_function_names(listing, fm, prev_f)
                has_alloc = any("AllocateWithFallbackHandler" in name for name in calls)
                has_ctor_call = False
                if ctor_addr:
                    has_ctor_call = ctor_f.getName() in calls
                if create_size <= 220 and has_alloc and (has_ctor_call or ctor_ok):
                    create_addr = f"0x{ep_int(prev_f):08x}"
                    stats["create"] += 1

            if not (create_addr or ctor_addr or dtor_addr):
                continue

            rows.append(
                {
                    "type_name": type_name,
                    "getter": f"0x{getter_ep:08x}",
                    "desc": f"0x{desc:08x}",
                    "tname_addr": f"0x{tname_addr:08x}" if tname_addr is not None else "",
                    "create": create_addr,
                    "ctor": ctor_addr,
                    "dtor": dtor_addr,
                    "vtbl_addr": vtbl_addr,
                    "getter_name": getter.getName(),
                    "create_name": prev_f.getName() if prev_f else "",
                    "ctor_name": ctor_f.getName() if ctor_f else "",
                    "dtor_name": dtor_f.getName() if dtor_f else "",
                }
            )

        rows.sort(key=lambda row: row["getter"])
        stats["rows"] = len(rows)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "type_name",
                "getter",
                "desc",
                "tname_addr",
                "create",
                "ctor",
                "dtor",
                "vtbl_addr",
                "getter_name",
                "create_name",
                "ctor_name",
                "dtor_name",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    print(
        "stats "
        f"getters={stats['getters']} rows={stats['rows']} "
        f"create={stats['create']} ctor={stats['ctor']} dtor={stats['dtor']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
