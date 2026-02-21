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
    ap.add_argument("--limit", type=int, default=60)
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    rows = data.get("vtable_candidates", [])[: args.limit]
    log(f"[start] vtable rows={len(rows)}")

    pyghidra.start(install_dir=args.ghidra_install)
    with pyghidra.open_program(
        str(args.binary_path),
        project_location=str(args.project_root),
        project_name=args.project_name,
        program_name=args.program,
        analyze=False,
        nested_project_location=False,
    ) as api:
        program = api.currentProgram
        st = program.getSymbolTable()
        af = program.getAddressFactory().getDefaultAddressSpace()
        from ghidra.program.model.symbol import SourceType

        tx = program.startTransaction("Apply vtable candidate labels")
        created = 0
        skipped = 0
        try:
            for idx, row in enumerate(rows, 1):
                addr_text = row["address"]
                run_len = int(row.get("run_len", 0))
                addr = af.getAddress(addr_text.lower())
                if addr is None:
                    skipped += 1
                    continue
                label = f"g_vtblCandidate_{addr_text[2:]}_len{run_len}"
                have = False
                for s in st.getSymbols(addr):
                    if s.getName() == label:
                        have = True
                        break
                if have:
                    skipped += 1
                    continue
                try:
                    sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    sym.setPrimary()
                    created += 1
                except Exception:
                    skipped += 1
                if idx % 10 == 0:
                    log(f"[progress] {idx}/{len(rows)} created={created} skipped={skipped}")
        finally:
            program.endTransaction(tx, True)
        log(f"[done] created={created} skipped={skipped}")


if __name__ == "__main__":
    main()
