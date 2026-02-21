#!/usr/bin/env python3
"""
Scan a function range for class-descriptor getter stubs:
  MOV EAX,<desc>; RET

Usage:
  .venv/bin/python new_scripts/scan_class_getters_fun6.py <start_hex> <end_hex> [out_csv] [project_root]

Examples:
  .venv/bin/python new_scripts/scan_class_getters_fun6.py 0x583000 0x594000
  .venv/bin/python new_scripts/scan_class_getters_fun6.py 0x583000 0x594000 tmp_decomp/getters.csv
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


def parse_hex(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 16)


def fmt(value: int | None) -> str:
    if value is None:
        return ""
    return f"0x{value:08x}"


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


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: scan_class_getters_fun6.py <start_hex> <end_hex> [out_csv] [project_root]")
        return 1

    start = parse_hex(sys.argv[1])
    end = parse_hex(sys.argv[2])
    out_csv = Path(sys.argv[3]) if len(sys.argv) >= 4 else None
    root = Path(sys.argv[4]) if len(sys.argv) >= 5 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        mem = program.getMemory()

        funcs = []
        it = fm.getFunctions(af.getAddress(fmt(start)), True)
        while it.hasNext():
            f = it.next()
            ep = int(str(f.getEntryPoint()), 16)
            if ep > end:
                break
            funcs.append(f)

        by_ep = {int(str(f.getEntryPoint()), 16): i for i, f in enumerate(funcs)}

        for f in funcs:
            ep = int(str(f.getEntryPoint()), 16)
            name = f.getName()
            if not name.startswith("FUN_"):
                continue
            if f.getBody().getNumAddresses() != 6:
                continue

            ins1 = listing.getInstructionAt(f.getEntryPoint())
            ins2 = listing.getInstructionAt(f.getEntryPoint().add(5))
            if ins1 is None or ins2 is None:
                continue

            s1 = str(ins1)
            if not s1.startswith("MOV EAX,0x") or str(ins2) != "RET":
                continue

            desc = int(s1.split("0x", 1)[1], 16)
            try:
                type_name_addr = mem.getInt(af.getAddress(fmt(desc))) & 0xFFFFFFFF
            except Exception:
                continue

            type_name = read_ascii_z(mem, af.getAddress(fmt(type_name_addr)))
            if not type_name or not type_name.startswith("T"):
                continue

            idx = by_ep[ep]
            prev_f = funcs[idx - 1] if idx > 0 else None
            next_f = funcs[idx + 1] if idx + 1 < len(funcs) else None
            next2_f = funcs[idx + 2] if idx + 2 < len(funcs) else None

            row = {
                "type_name": type_name,
                "getter": fmt(ep),
                "getter_name": name,
                "desc": fmt(desc),
                "tname_addr": fmt(type_name_addr),
                "create": fmt(int(str(prev_f.getEntryPoint()), 16)) if prev_f else "",
                "create_name": prev_f.getName() if prev_f else "",
                "ctor": fmt(int(str(next_f.getEntryPoint()), 16)) if next_f else "",
                "ctor_name": next_f.getName() if next_f else "",
                "dtor": fmt(int(str(next2_f.getEntryPoint()), 16)) if next2_f else "",
                "dtor_name": next2_f.getName() if next2_f else "",
            }
            rows.append(row)

    rows.sort(key=lambda r: (r["getter"], r["type_name"]))

    print(
        "type_name,getter,desc,tname_addr,create,ctor,dtor,"
        "getter_name,create_name,ctor_name,dtor_name"
    )
    for r in rows:
        print(
            ",".join(
                [
                    r["type_name"],
                    r["getter"],
                    r["desc"],
                    r["tname_addr"],
                    r["create"],
                    r["ctor"],
                    r["dtor"],
                    r["getter_name"],
                    r["create_name"],
                    r["ctor_name"],
                    r["dtor_name"],
                ]
            )
        )

    if out_csv is not None:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "type_name",
                    "getter",
                    "desc",
                    "tname_addr",
                    "create",
                    "ctor",
                    "dtor",
                    "getter_name",
                    "create_name",
                    "ctor_name",
                    "dtor_name",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"[saved] {out_csv} rows={len(rows)}")
    else:
        print(f"[done] rows={len(rows)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

