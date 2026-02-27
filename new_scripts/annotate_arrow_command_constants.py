#!/usr/bin/env python3
"""
Annotate immediate 0x64/0x65 constants in split-arrow handlers.

Adds EOL comments:
  0x64 -> EArrowSplitCommandId::ARROW_SPLIT_CMD_LEFT
  0x65 -> EArrowSplitCommandId::ARROW_SPLIT_CMD_RIGHT

Usage:
  .venv/bin/python new_scripts/annotate_arrow_command_constants.py
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

TARGET_FUNCS = (
    "HandleTradeArrowAutoRepeatTickAndDispatch",
    "HandleSplitArrowAutoRepeatTickAndDispatch_Offset90",
    "HandleSplitArrowAutoRepeatTickAndDispatch_Offset84",
    "HandleTaggedArrowAutoRepeatTickAndDispatch_Offset84",
    "HandleSplitArrowMousePhaseStateAndDispatchCommand64or65",
    "HandleTransportPictureSplitArrowCommand64or65",
    "HandleShipFractionClusterSplitArrowCommand64or65",
    "HandleProductionClusterValuePanelSplitArrowCommand64or65AndForward",
)


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

        fm = program.getFunctionManager()
        listing = program.getListing()

        tx = program.startTransaction("Annotate arrow command constants")
        try:
            changed = 0
            scanned = 0
            for fn in fm.getFunctions(True):
                name = fn.getName()
                if name not in TARGET_FUNCS:
                    continue
                scanned += 1
                ins_it = listing.getInstructions(fn.getBody(), True)
                while ins_it.hasNext():
                    ins = ins_it.next()
                    comment = None
                    for oi in range(ins.getNumOperands()):
                        sc = ins.getScalar(oi)
                        if sc is None:
                            continue
                        try:
                            val = int(sc.getUnsignedValue())
                        except Exception:
                            continue
                        if val == 0x64:
                            comment = (
                                "EArrowSplitCommandId::ARROW_SPLIT_CMD_LEFT (0x64)"
                            )
                            break
                        if val == 0x65:
                            comment = (
                                "EArrowSplitCommandId::ARROW_SPLIT_CMD_RIGHT (0x65)"
                            )
                            break
                    if comment is None:
                        continue
                    prev = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
                    if prev == comment:
                        continue
                    listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, comment)
                    changed += 1
                    print(f"[annotated] {ins.getAddress()} {name}: {comment}")

        finally:
            program.endTransaction(tx, True)

        program.save("annotate arrow command constants", None)
        print(f"[done] scanned_functions={scanned} annotations_set={changed}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
