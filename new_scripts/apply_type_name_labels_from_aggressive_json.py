#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pyghidra


def log(msg: str):
    print(msg, flush=True)


def sanitize_label(text: str) -> str:
    t = re.sub(r"[^A-Za-z0-9_]", "_", text.strip())
    t = re.sub(r"_+", "_", t).strip("_")
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args()

    rx = re.compile(
        r"^(?:[TC][A-Za-z0-9_]*(?:Dialog|Window|View|Frame|Wnd)|"
        r"CMainFrame|CMcWindow|TradeScreenView|TransportScreenView|CityProductionView|TerrainMapView)$"
    )

    data = json.loads(args.input.read_text())
    candidates = []
    for row in data.get("class_string_hits", []):
        s = row.get("text", "")
        if not rx.match(s):
            continue
        candidates.append((row["address"], s, int(row.get("ref_count", 0))))

    # Aggressive but deterministic: higher ref count first, then shorter canonical names.
    candidates.sort(key=lambda x: (x[2], -len(x[1])), reverse=True)
    if args.limit > 0:
        candidates = candidates[: args.limit]

    log(f"[start] candidates={len(candidates)} from {args.input}")
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
        log("[start] opened program with analyze=False")
        try:
            st = program.getSymbolTable()
            af = program.getAddressFactory().getDefaultAddressSpace()
            from ghidra.program.model.symbol import SourceType

            tx = program.startTransaction("Apply aggressive type-name labels")
            created = 0
            skipped = 0
            failed = 0
            try:
                for idx, (addr_text, text, rc) in enumerate(candidates, 1):
                    addr = af.getAddress(addr_text.lower())
                    if addr is None:
                        log(f"[skip] bad_addr {addr_text} {text}")
                        skipped += 1
                        continue
                    label = f"sTypeName_{sanitize_label(text)}"
                    have = False
                    syms = st.getSymbols(addr)
                    for s in syms:
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
                        if created <= 5:
                            log(f"[create] {addr_text} -> {label}")
                        if idx % 10 == 0:
                            log(f"[progress] {idx}/{len(candidates)} created={created} skipped={skipped} failed={failed}")
                    except Exception:
                        try:
                            alt = f"{label}_{addr_text[2:]}"
                            sym = st.createLabel(addr, alt, SourceType.USER_DEFINED)
                            sym.setPrimary()
                            created += 1
                            if created <= 5:
                                log(f"[create] {addr_text} -> {alt}")
                        except Exception as ex:
                            failed += 1
                            log(f"[fail] {addr_text} {text} err={ex}")
            finally:
                program.endTransaction(tx, True)
            log(f"[done] created={created} skipped={skipped} failed={failed}")
        finally:
            pass


if __name__ == "__main__":
    main()
