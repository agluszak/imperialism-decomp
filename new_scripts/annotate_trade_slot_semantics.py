#!/usr/bin/env python3
"""
Attach concise slot-semantics comments to key trade dispatch handlers.

Goal:
  Improve decompiler readability around TradeControl slot usage discovered via
  high-confidence re-decomp work (e.g., 0x00583BD0).
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TARGET_COMMENTS = {
    0x00583BD0: (
        "Trade auto-repeat dispatcher. Uses TradeControl vslots:\n"
        "- slot +0x16c (CtrlSlot91): readiness gate using dispatchArg\n"
        "- slot +0x40 (CtrlSlot16): emits split-arrow command dispatch\n"
        "Command IDs observed: LEFT=0x64, RIGHT=0x65, synthetic tick path uses 100."
    ),
    0x00401B3B: (
        "Thunk mirror for trade auto-repeat dispatcher (0x00583BD0). "
        "Preserve bridge call shape for matching."
    ),
    0x00586E70: (
        "Trade move handler in CtrlSlot16-style shape:\n"
        "  (commandId, eventArg, eventExtra)."
    ),
    0x005873E0: (
        "Trade sell handler in CtrlSlot16-style shape:\n"
        "  (commandId, eventArg, eventExtra)."
    ),
    0x005869C0: (
        "Production split-arrow handler in CtrlSlot16-style shape:\n"
        "  (commandId, eventArg, eventExtra)."
    ),
}


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
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        tx = program.startTransaction("Annotate trade slot semantics")
        ok = skip = miss = 0
        try:
            for addr_i, text in TARGET_COMMENTS.items():
                fn = fm.getFunctionAt(af.getAddress(f"0x{addr_i:08x}"))
                if fn is None:
                    miss += 1
                    print(f"[miss] 0x{addr_i:08x}")
                    continue
                old = fn.getComment() or ""
                if old == text:
                    skip += 1
                    continue
                fn.setComment(text)
                ok += 1
                print(f"[comment] 0x{addr_i:08x} {fn.getName()}")
        finally:
            program.endTransaction(tx, True)

        program.save("annotate trade slot semantics", None)
        print(f"[done] ok={ok} skip={skip} miss={miss}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

