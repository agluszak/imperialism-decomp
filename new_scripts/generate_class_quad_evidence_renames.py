#!/usr/bin/env python3
"""
Generate high-confidence renames from class-quad CSV rows using decomp evidence.

Input CSV columns (expected):
  type_name,getter,desc,tname_addr,create,ctor,dtor

Output CSV columns:
  address,new_name,comment

Usage:
  .venv/bin/python new_scripts/generate_class_quad_evidence_renames.py \
    <input_csv> <output_csv> [project_root]
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if not t:
        raise ValueError("empty address")
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def is_generic_name(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) < 2:
        print(
            "usage: generate_class_quad_evidence_renames.py "
            "<input_csv> <output_csv> [project_root]"
        )
        return 1

    in_csv = Path(argv[0])
    out_csv = Path(argv[1])
    root = Path(argv[2]) if len(argv) >= 3 else Path(__file__).resolve().parents[1]

    if not in_csv.exists():
        print(f"missing input csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        print("no input rows")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        monitor = ConsoleTaskMonitor()

        # Preload current symbol-name ownership to avoid collisions.
        name_to_addr = {}
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            name = f.getName()
            if name not in name_to_addr:
                name_to_addr[name] = f.getEntryPoint().getOffset()

        ifc = DecompInterface()
        ifc.openProgram(program)

        decomp_cache = {}

        def get_func(addr_text: str):
            if not addr_text:
                return None
            try:
                addr = af.getAddress(f"0x{parse_hex(addr_text):08x}")
            except Exception:
                return None
            return fm.getFunctionAt(addr)

        def decomp_text(func):
            off = func.getEntryPoint().getOffset()
            if off in decomp_cache:
                return decomp_cache[off]
            try:
                res = ifc.decompileFunction(func, 60, monitor)
                if not res.decompileCompleted():
                    txt = ""
                else:
                    txt = res.getDecompiledFunction().getC()
            except Exception:
                txt = ""
            decomp_cache[off] = txt
            return txt

        proposals = []
        seen_addrs = set()
        seen_names = set()
        stats = {
            "create_candidate": 0,
            "ctor_candidate": 0,
            "dtor_candidate": 0,
            "create_emit": 0,
            "ctor_emit": 0,
            "dtor_emit": 0,
            "skip_non_generic": 0,
            "skip_collision": 0,
            "skip_no_evidence": 0,
            "skip_bad_addr": 0,
        }

        def maybe_add(func, new_name: str, comment: str, kind: str):
            nonlocal proposals
            if func is None:
                stats["skip_bad_addr"] += 1
                return

            off = func.getEntryPoint().getOffset()
            old_name = func.getName()
            if not is_generic_name(old_name):
                stats["skip_non_generic"] += 1
                return
            if off in seen_addrs or new_name in seen_names:
                stats["skip_collision"] += 1
                return
            existing = name_to_addr.get(new_name)
            if existing is not None and existing != off:
                stats["skip_collision"] += 1
                return

            seen_addrs.add(off)
            seen_names.add(new_name)
            proposals.append(
                {
                    "address": f"0x{off:08x}",
                    "new_name": new_name,
                    "comment": comment,
                }
            )
            stats[f"{kind}_emit"] += 1

        for row in rows:
            tname = (row.get("type_name") or "").strip()
            if not tname:
                continue

            # create
            create_addr = (row.get("create") or "").strip()
            if create_addr:
                stats["create_candidate"] += 1
                f = get_func(create_addr)
                if f is not None:
                    ctext = decomp_text(f)
                    if "AllocateWithFallbackHandler" in ctext:
                        maybe_add(
                            f,
                            f"Create{tname}Instance",
                            f"[ClassQuad] create inferred for {tname}; alloc factory pattern.",
                            "create",
                        )
                    else:
                        stats["skip_no_evidence"] += 1

            # ctor
            ctor_addr = (row.get("ctor") or "").strip()
            if ctor_addr:
                stats["ctor_candidate"] += 1
                f = get_func(ctor_addr)
                if f is not None:
                    ctext = decomp_text(f)
                    has_vtbl_symbol = f"g_vtbl{tname}" in ctext
                    has_vtbl_store = "*param_1 = &PTR_" in ctext or "*this = &PTR_" in ctext
                    if has_vtbl_symbol or has_vtbl_store:
                        maybe_add(
                            f,
                            f"Construct{tname}",
                            f"[ClassQuad] ctor inferred for {tname}; vtable install pattern.",
                            "ctor",
                        )
                    else:
                        stats["skip_no_evidence"] += 1

            # dtor
            dtor_addr = (row.get("dtor") or "").strip()
            if dtor_addr:
                stats["dtor_candidate"] += 1
                f = get_func(dtor_addr)
                if f is not None:
                    ctext = decomp_text(f)
                    if "FreeHeapBufferIfNotNull" in ctext and "& 1" in ctext:
                        maybe_add(
                            f,
                            f"Destroy{tname}",
                            f"[ClassQuad] dtor inferred for {tname}; free-if-owned pattern.",
                            "dtor",
                        )
                    else:
                        stats["skip_no_evidence"] += 1

        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["address", "new_name", "comment"])
            writer.writeheader()
            writer.writerows(proposals)

        print(f"[done] input_rows={len(rows)} output_rows={len(proposals)} -> {out_csv}")
        for k in sorted(stats):
            print(f"  {k}={stats[k]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
