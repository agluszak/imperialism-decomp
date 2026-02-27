#!/usr/bin/env python3
"""
Normalize nested WrapperFor names into single-layer wrapper names.

Example:
  WrapperFor_WrapperFor_GetOrCreateHandleMapObjectByHandle_At00612736_At004945f0
->WrapperFor_GetOrCreateHandleMapObjectByHandle_At004945f0

Usage:
  .venv/bin/python new_scripts/normalize_wrapper_chain_names.py [out_csv] [project_root]
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

WRAP_PREFIX = "WrapperFor_"
TRAIL_ADDR_RE = re.compile(r"_At[0-9a-fA-F]{8}$")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "UnknownTarget"
    if s[0].isdigit():
        s = "_" + s
    return s


def collapse_wrapper_name(name: str, addr_hex: str) -> str | None:
    if not name.startswith(WRAP_PREFIX + WRAP_PREFIX):
        return None

    core = name
    while core.startswith(WRAP_PREFIX):
        core = core[len(WRAP_PREFIX) :]

    while TRAIL_ADDR_RE.search(core):
        core = TRAIL_ADDR_RE.sub("", core)

    core = sanitize_symbol_name(core)
    return f"{WRAP_PREFIX}{core}_At{addr_hex}"


def main() -> int:
    out_csv = (
        Path(sys.argv[1])
        if len(sys.argv) >= 2
        else Path("tmp_decomp/wrapper_chain_normalize_candidates.csv")
    )
    root = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path(__file__).resolve().parents[1]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    existing_names = set()

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()

        it = fm.getFunctions(True)
        funcs = []
        while it.hasNext():
            f = it.next()
            funcs.append(f)
            existing_names.add(f.getName())

        for f in funcs:
            old_name = f.getName()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            addr_hex = f"{addr:08x}"
            new_name = collapse_wrapper_name(old_name, addr_hex)
            if new_name is None:
                continue
            if new_name == old_name:
                continue
            if new_name in existing_names and new_name != old_name:
                continue

            rows.append(
                {
                    "address": f"0x{addr_hex}",
                    "new_name": new_name,
                    "comment": (
                        f"[WrapperNormalize] collapsed nested wrapper chain from {old_name}"
                    ),
                    "old_name": old_name,
                }
            )

    rows.sort(key=lambda r: r["address"])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment", "old_name"])
        wr.writeheader()
        wr.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(f"{r['address']},{r['old_name']} -> {r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
