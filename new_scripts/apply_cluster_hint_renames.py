#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyghidra


def log(msg: str):
    print(msg, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--min-score", type=int, default=2)
    ap.add_argument("--require-non_generic-callee", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    rows = []
    for r in data.get("rows", []):
        cur = r.get("current_name", "")
        score = int(r.get("domain_score", 0))
        dom = r.get("domain", "Unknown")
        addr = r.get("address", "0x00000000")
        if not cur.startswith("Cluster_Vcall_"):
            continue
        if score < args.min_score or dom == "Unknown":
            continue
        if args.require_non_generic_callee:
            raw = str(r.get("top_callees", ""))
            callees = [x.strip() for x in raw.split(";") if x.strip()]
            good = False
            for c in callees:
                cl = c.lower()
                if c.startswith("FUN_") or c.startswith("Cluster_"):
                    continue
                if c.startswith("thunk_") and not any(k in cl for k in ("trade", "city", "turn", "event", "diplom", "battle", "map", "dialog", "window", "view", "nation")):
                    continue
                good = True
                break
            if not good:
                continue
        addr_hex = addr[2:] if addr.startswith("0x") else addr
        new_name = f"Cluster_{dom}Hint_{addr_hex}"
        rows.append((addr, cur, new_name, score, dom))

    rows.sort(key=lambda x: x[3], reverse=True)
    log(f"[start] candidates={len(rows)} min_score={args.min_score}")
    for r in rows[:20]:
        log(f"[plan] {r[0]} {r[1]} -> {r[2]} score={r[3]} dom={r[4]}")
    if args.dry_run:
        return

    pyghidra.start(install_dir=args.ghidra_install)
    with pyghidra.open_program(
        str(args.binary_path),
        project_location=str(args.project_root),
        project_name=args.project_name,
        program_name=args.program,
        analyze=False,
        nested_project_location=False,
    ) as api:
        p = api.currentProgram
        fm = p.getFunctionManager()
        st = p.getSymbolTable()
        af = p.getAddressFactory().getDefaultAddressSpace()
        from ghidra.program.model.symbol import SourceType

        tx = p.startTransaction("Apply cluster semantic hints")
        renamed = 0
        skipped = 0
        failed = 0
        try:
            for i, (addr_text, cur_name, new_name, score, dom) in enumerate(rows, 1):
                addr = af.getAddress(addr_text.lower())
                if addr is None:
                    skipped += 1
                    continue
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    skipped += 1
                    continue
                if fn.getName() != cur_name:
                    skipped += 1
                    continue
                coll = False
                for s in st.getSymbols(new_name):
                    if s.getAddress() != addr:
                        coll = True
                        break
                if coll:
                    skipped += 1
                    continue
                try:
                    fn.setName(new_name, SourceType.USER_DEFINED)
                    renamed += 1
                except Exception as ex:
                    failed += 1
                    log(f"[fail] {addr_text} {cur_name} -> {new_name} err={ex}")
                if i % 10 == 0:
                    log(f"[progress] {i}/{len(rows)} renamed={renamed} skipped={skipped} failed={failed}")
        finally:
            p.endTransaction(tx, True)
        log(f"[done] renamed={renamed} skipped={skipped} failed={failed}")


if __name__ == "__main__":
    main()
