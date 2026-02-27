#!/usr/bin/env python3
"""
Generate conservative renames for tiny orphan FUN_* wrappers.

Target population:
  - functions named FUN_*
  - zero incoming code xrefs
  - tiny body (default <= 3 instructions)

Recognized shapes:
  - getter: MOV <reg>, [ECX + off]; RET
  - setter: MOV <reg>, [ESP + 0x4]; MOV [ECX + off], <reg>; RET 0x4
  - return zero: XOR EAX,EAX; RET
  - return this: MOV EAX,ECX; RET
  - return -1: OR AX,0xffff; RET
  - this-adjust tail-jump: ADD ECX,imm; JMP <target>
  - vcall forward: MOV EAX,[ECX + ...]; JMP [EAX + off]

Output CSV:
  address,new_name,comment
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def classify_tiny_shape(insns: list[str]) -> tuple[str, str] | None:
    up = [s.upper() for s in insns]
    if len(up) == 2:
        m_get = re.match(r"^MOV\s+([A-Z0-9]+),DWORD PTR \[ECX \+ 0X([0-9A-F]+)\]$", up[0])
        if m_get and up[1].startswith("RET"):
            reg = m_get.group(1)
            off = m_get.group(2).lower()
            return (f"OrphanTiny_GetDwordEcxOffset_{off}", f"tiny getter via {reg} from [ECX+0x{off}]")

        m_getw = re.match(r"^MOV\s+AX,WORD PTR \[ECX \+ 0X([0-9A-F]+)\]$", up[0])
        if m_getw and up[1].startswith("RET"):
            off = m_getw.group(1).lower()
            return (f"OrphanTiny_GetWordEcxOffset_{off}", f"tiny getter word from [ECX+0x{off}]")

        if up[0] == "XOR EAX,EAX" and up[1].startswith("RET"):
            return ("OrphanTiny_ReturnZero", "tiny return-zero wrapper")

        if up[0] == "MOV EAX,ECX" and up[1].startswith("RET"):
            return ("OrphanTiny_ReturnThis", "tiny return-this wrapper")

        if up[0].startswith("OR AX,0XFFFF") and up[1].startswith("RET"):
            return ("OrphanTiny_ReturnMinusOneWord", "tiny return -1 (word) wrapper")

        m_adj = re.match(r"^ADD\s+ECX,0X([0-9A-F]+)$", up[0])
        if m_adj and up[1].startswith("JMP "):
            imm = m_adj.group(1).lower()
            return (f"OrphanTiny_ThisAdjustJump_{imm}", f"this-adjust tail jump by +0x{imm}")

        if up[0].startswith("MOV EAX,DWORD PTR [ECX") and up[1].startswith("JMP DWORD PTR [EAX + 0X"):
            m_slot = re.search(r"\[EAX \+ 0X([0-9A-F]+)\]", up[1])
            slot = m_slot.group(1).lower() if m_slot else "xx"
            return (f"OrphanTiny_VcallForward_Slot_{slot}", f"tiny virtual-call forwarder slot 0x{slot}")

    if len(up) == 3:
        m_set = re.match(r"^MOV\s+([A-Z0-9]+),DWORD PTR \[ESP \+ 0X4\]$", up[0])
        m_store = re.match(r"^MOV\s+DWORD PTR \[ECX \+ 0X([0-9A-F]+)\],([A-Z0-9]+)$", up[1])
        if m_set and m_store and up[2].startswith("RET 0X4"):
            off = m_store.group(1).lower()
            return (f"OrphanTiny_SetDwordEcxOffset_{off}", f"tiny setter dword to [ECX+0x{off}]")

        m_setw = re.match(r"^MOV\s+AX,WORD PTR \[ESP \+ 0X4\]$", up[0])
        m_storew = re.match(r"^MOV\s+WORD PTR \[ECX \+ 0X([0-9A-F]+)\],AX$", up[1])
        if m_setw and m_storew and up[2].startswith("RET 0X4"):
            off = m_storew.group(1).lower()
            return (f"OrphanTiny_SetWordEcxOffset_{off}", f"tiny setter word to [ECX+0x{off}]")

        if up[0].startswith("MOV EAX,DWORD PTR [ECX") and up[1].startswith("FLD FLOAT PTR "):
            return ("OrphanTiny_LoadFloatByIndexedTable", "tiny indexed float-table loader")

    return None


def ensure_unique(existing: set[str], desired: str, addr: int) -> str:
    if desired not in existing:
        return desired
    base = f"{desired}_At{addr:08x}"
    cur = base
    idx = 2
    while cur in existing:
        cur = f"{base}_{idx}"
        idx += 1
    return cur


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--addr-min", default="0x00400000")
    ap.add_argument("--addr-max", default="0x006fffff")
    ap.add_argument("--max-instructions", type=int, default=3)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    out_csv = Path(args.out_csv)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        existing_names = set()
        it = fm.getFunctions(True)
        funcs = []
        while it.hasNext():
            f = it.next()
            funcs.append(f)
            existing_names.add(f.getName())

        reserved = set(existing_names)

        for f in funcs:
            name = f.getName()
            if not name.startswith("FUN_"):
                continue
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr < lo or addr > hi:
                continue

            # No incoming code xrefs.
            refs = rm.getReferencesTo(af.getAddress(f"0x{addr:08x}"))
            code_xrefs = 0
            for ref in refs:
                from_addr = ref.getFromAddress()
                if from_addr is None:
                    continue
                if fm.getFunctionContaining(from_addr) is not None:
                    code_xrefs += 1
            if code_xrefs != 0:
                continue

            insns = []
            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                insns.append(str(ins_it.next()))
                if len(insns) > args.max_instructions:
                    break
            if not insns or len(insns) > args.max_instructions:
                continue

            cls = classify_tiny_shape(insns)
            if cls is None:
                continue
            base, desc = cls
            desired = f"{base}_{addr:08x}"
            new_name = ensure_unique(reserved, desired, addr)
            reserved.add(new_name)
            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "new_name": new_name,
                    "comment": f"[TinyOrphan] {desc}; pattern={' | '.join(insns)}",
                }
            )

    rows.sort(key=lambda r: r["address"])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"range=0x{lo:08x}-0x{hi:08x} max_instructions={args.max_instructions}"
    )
    for r in rows[:200]:
        print(f"{r['address']},{r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
