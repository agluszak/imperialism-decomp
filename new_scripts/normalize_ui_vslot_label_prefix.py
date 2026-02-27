#!/usr/bin/env python3
"""
Rename UI slot labels from g_vtbl* prefix to g_vslot* prefix.

This avoids polluting class/vtable inventory scripts that treat g_vtblT* as class
anchors.

Target pattern:
  g_vtbl..._SlotXXXX_<slotName>

Rename:
  g_vslot..._SlotXXXX_<slotName>

Usage:
  .venv/bin/python new_scripts/normalize_ui_vslot_label_prefix.py
  .venv/bin/python new_scripts/normalize_ui_vslot_label_prefix.py --apply
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
RX_SLOT = re.compile(r"^g_vtbl.+_Slot[0-9A-Fa-f]{4}_.+$")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write renames")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.symbol import SourceType

        st = program.getSymbolTable()

        candidates = []
        it = st.getSymbolIterator()
        while it.hasNext():
            sym = it.next()
            old = sym.getName()
            if not RX_SLOT.match(old):
                continue
            new = old.replace("g_vtbl", "g_vslot", 1)
            if old == new:
                continue
            candidates.append((sym, old, new))

        print(f"[candidates] {len(candidates)}")
        for _sym, old, new in candidates[:240]:
            print(f"  {old} -> {new}")
        if len(candidates) > 240:
            print(f"  ... ({len(candidates)-240} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write renames")
            return 0

        tx = program.startTransaction("Normalize ui vslot label prefix")
        ok = skip = fail = 0
        try:
            for sym, old, new in candidates:
                try:
                    if old == new:
                        skip += 1
                        continue
                    sym.setName(new, SourceType.USER_DEFINED)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {old} -> {new} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("normalize ui vslot label prefix", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
