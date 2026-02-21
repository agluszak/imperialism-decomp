#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyghidra


def log(msg: str):
    print(msg, flush=True)


def family_from_offsets(offsets: list[int]) -> str:
    s = set(offsets)
    if {0xA4, 0xA8, 0x1C8}.issubset(s):
        if 0x1E4 in s:
            return "UiControlA4A8_1C8_1E4"
        if 0x30 in s:
            return "UiControlA4A8_1C8_30"
        return "UiControlA4A8_1C8"
    if {0x24, 0x2C, 0x48, 0x4C, 0x68, 0x78, 0x84, 0x88}.issubset(s):
        return "UiPageGrid244C6888"
    if {0x18, 0x1C, 0x28, 0x38, 0x44, 0x48, 0x4C}.issubset(s):
        return "StateMachine18_4C"
    if {0x1C, 0x28, 0x84, 0x94, 0xA4}.issubset(s):
        return "UiPanel1C28_84A4"
    if s == {0x14}:
        return "SingleSlot14"
    if s == {0x38}:
        return "SingleSlot38"
    top = sorted(offsets)[:3]
    return "Vcall_%s" % "_".join([f"{x:02X}" for x in top])


def parse_offsets(off_list: list[str]) -> list[int]:
    out = []
    for x in off_list:
        if isinstance(x, str) and x.startswith("0x"):
            out.append(int(x, 16))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", default="imperialism-decomp")
    ap.add_argument("--program", default="Imperialism.exe")
    ap.add_argument("--binary-path", type=Path, default=Path("/home/andrzej.gluszak/code/personal/imperialism_knowledge/Imperialism.exe"))
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--min-vcalls", type=int, default=18)
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--min-family-support", type=int, default=2)
    ap.add_argument("--skip-small-body-bytes", type=int, default=6)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data = json.loads(args.input.read_text())
    raw = []
    for r in data.get("virtual_call_functions", []):
        fn = r.get("function", "")
        vc = int(r.get("vcall_count", 0))
        if not fn.startswith("FUN_"):
            continue
        if vc < args.min_vcalls:
            continue
        offs = parse_offsets(r.get("offsets", []))
        fam = family_from_offsets(offs)
        addr = r.get("address", "0x00000000")
        addr_hex = addr[2:] if isinstance(addr, str) and addr.startswith("0x") else addr
        new_name = f"Cluster_{fam}_{addr_hex}"
        raw.append((addr, fn, new_name, vc, fam))

    # Stricter family guard: require minimum support for generic families.
    fam_counts = {}
    for _, _, _, _, fam in raw:
        fam_counts[fam] = fam_counts.get(fam, 0) + 1

    cands = []
    skipped_low_support = 0
    for row in raw:
        fam = row[4]
        # keep known strong families; tighten generic singleton families
        if fam.startswith("Vcall_") and fam_counts.get(fam, 0) < args.min_family_support:
            skipped_low_support += 1
            continue
        cands.append(row)

    cands.sort(key=lambda x: x[3], reverse=True)
    if args.limit > 0:
        cands = cands[: args.limit]
    log(
        f"[start] candidates={len(cands)} min_vcalls={args.min_vcalls} "
        f"limit={args.limit} skipped_low_support={skipped_low_support}"
    )
    for row in cands[:10]:
        log(f"[plan] {row[0]} {row[1]} -> {row[2]} vcalls={row[3]} fam={row[4]}")
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
        program = api.currentProgram
        fm = program.getFunctionManager()
        syms = program.getSymbolTable()
        af = program.getAddressFactory().getDefaultAddressSpace()
        from ghidra.program.model.symbol import SourceType

        tx = program.startTransaction("Batch rename FUN by vcall cluster")
        renamed = 0
        skipped = 0
        failed = 0
        skipped_small_body = 0
        skipped_name_collision = 0
        try:
            for i, (addr_text, old_name, new_name, vc, fam) in enumerate(cands, 1):
                addr = af.getAddress(addr_text.lower())
                if addr is None:
                    skipped += 1
                    continue
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    skipped += 1
                    continue
                cur = fn.getName()
                if not cur.startswith("FUN_"):
                    skipped += 1
                    continue
                body_bytes = int(fn.getBody().getNumAddresses())
                if body_bytes < args.skip_small_body_bytes:
                    skipped += 1
                    skipped_small_body += 1
                    continue
                if cur == new_name:
                    skipped += 1
                    continue
                # Strict collision guard: if target name exists elsewhere, skip.
                coll = False
                for s in syms.getSymbols(new_name):
                    if s.getAddress() != fn.getEntryPoint():
                        coll = True
                        break
                if coll:
                    skipped += 1
                    skipped_name_collision += 1
                    continue
                try:
                    fn.setName(new_name, SourceType.USER_DEFINED)
                    renamed += 1
                    if i % 10 == 0:
                        log(f"[progress] {i}/{len(cands)} renamed={renamed} skipped={skipped} failed={failed}")
                except Exception as ex:
                    failed += 1
                    log(f"[fail] {addr_text} {cur} -> {new_name} err={ex}")
        finally:
            program.endTransaction(tx, True)
        log(
            f"[done] renamed={renamed} skipped={skipped} failed={failed} "
            f"skipped_small_body={skipped_small_body} skipped_name_collision={skipped_name_collision}"
        )


if __name__ == "__main__":
    main()
