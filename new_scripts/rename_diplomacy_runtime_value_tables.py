#!/usr/bin/env python3
"""
Rename diplomacy runtime lookup tables used by action/grant policy handlers.
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


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
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.listing import CodeUnit
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        st = program.getSymbolTable()
        listing = program.getListing()

        targets = [
            (
                "0x0069695c",
                "g_awDiplomacyTradePolicyIconValueTable",
                "Runtime-initialized diplomacy trade-policy value lookup table.",
            ),
            (
                "0x00696948",
                "g_awDiplomacyGrantAndTradePolicyValueTable",
                "Runtime-initialized diplomacy grant/trade-policy value lookup table.",
            ),
        ]

        tx = program.startTransaction("Rename diplomacy runtime value tables")
        try:
            for addr_txt, name, note in targets:
                addr = af.getAddress(addr_txt)
                existing = [s for s in st.getSymbols(addr) if not s.isExternal()]
                if existing:
                    primary = existing[0]
                    if primary.getName() != name:
                        primary.setName(name, SourceType.USER_DEFINED)
                else:
                    st.createLabel(addr, name, SourceType.USER_DEFINED)

                old = listing.getComment(CodeUnit.EOL_COMMENT, addr)
                if not old:
                    listing.setComment(addr, CodeUnit.EOL_COMMENT, note)
                elif note not in old:
                    listing.setComment(addr, CodeUnit.EOL_COMMENT, f"{old} | {note}")

                print(f"[ok] {addr_txt} -> {name}")
        finally:
            program.endTransaction(tx, True)

        program.save("rename diplomacy runtime value tables", None)
        print("[saved]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
