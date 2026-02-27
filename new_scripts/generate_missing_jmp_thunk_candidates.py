#!/usr/bin/env python3
"""
Generate CSV candidates for missing single-JMP thunk entries.

Usage:
  .venv/bin/python new_scripts/generate_missing_jmp_thunk_candidates.py \
      [--start 0x00400000] [--end 0x00410000] [--name-regex REGEX] \
      [out_csv] [project_root]
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


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
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


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    start = 0x00400000
    end = 0x00410000
    name_rx = ".*"
    out_csv = root / "tmp_decomp/missing_jmp_thunk_candidates.csv"

    argv = sys.argv[1:]
    i = 0
    pos = []
    while i < len(argv):
        tok = argv[i]
        if tok == "--start" and i + 1 < len(argv):
            start = parse_hex(argv[i + 1])
            i += 2
            continue
        if tok == "--end" and i + 1 < len(argv):
            end = parse_hex(argv[i + 1])
            i += 2
            continue
        if tok == "--name-regex" and i + 1 < len(argv):
            name_rx = argv[i + 1]
            i += 2
            continue
        pos.append(tok)
        i += 1

    if len(pos) >= 1:
        out_csv = Path(pos[0])
        if not out_csv.is_absolute():
            out_csv = root / out_csv
    if len(pos) >= 2:
        root = Path(pos[1]).resolve()

    target_re = re.compile(name_rx, re.IGNORECASE)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    seen_sources: set[int] = set()

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()
        start_addr = af.getAddress(f"0x{start:08x}")
        end_addr = af.getAddress(f"0x{end:08x}")

        ins_it = listing.getInstructions(start_addr, True)
        while ins_it.hasNext():
            ins = ins_it.next()
            a = ins.getAddress()
            if a.compareTo(end_addr) >= 0:
                break
            src = a.getOffset() & 0xFFFFFFFF
            if src in seen_sources:
                continue
            if str(ins.getMnemonicString()).upper() != "JMP":
                continue
            flows = ins.getFlows()
            if flows is None or len(flows) != 1:
                continue
            dst = flows[0]
            target = fm.getFunctionAt(dst)
            if target is None:
                continue
            tname = target.getName()
            if tname.startswith("FUN_") or tname.startswith("thunk_FUN_"):
                continue
            if tname.startswith("thunk_"):
                continue
            if not target_re.search(tname):
                continue

            f_at_src = fm.getFunctionAt(a)
            f_contains_src = fm.getFunctionContaining(a)
            if f_contains_src is not None and f_at_src is None:
                continue

            source_name = ""
            source_is_generic = "0"
            if f_at_src is not None:
                source_name = f_at_src.getName()
                if source_name.startswith("FUN_") or source_name.startswith("thunk_FUN_"):
                    source_is_generic = "1"
                # Avoid renaming already-curated source functions.
                if source_is_generic != "1":
                    continue

            new_name = f"thunk_{tname}"
            rows.append(
                {
                    "address": f"0x{src:08x}",
                    "new_name": new_name,
                    "comment": f"Single-JMP thunk to {tname}",
                    "target_addr": str(target.getEntryPoint()),
                    "target_name": tname,
                    "has_function_at_source": "1" if f_at_src is not None else "0",
                    "source_name": source_name,
                    "source_is_generic": source_is_generic,
                }
            )
            seen_sources.add(src)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "new_name",
                "comment",
                "target_addr",
                "target_name",
                "has_function_at_source",
                "source_name",
                "source_is_generic",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(
        f"[saved] {out_csv} rows={len(rows)} "
        f"range=0x{start:08x}-0x{end:08x} name_regex={name_rx}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
