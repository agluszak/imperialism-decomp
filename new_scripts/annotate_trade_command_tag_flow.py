#!/usr/bin/env python3
"""
Focused dehardcode pass for trade command/tag flow handlers.

Actions:
  - Create /Imperialism/ETradeUiActionCommandIdRaw (4-byte enum): 0x67..0x6A
  - Add EOL comments for these command IDs in trade handlers
  - Add/update plate comments on key trade command/tag functions
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

ENUM_VALUES = [
    ("TRADE_UI_ACTION_CMD_67", 0x67),
    ("TRADE_UI_ACTION_CMD_68", 0x68),
    ("TRADE_UI_ACTION_CMD_69", 0x69),
    ("TRADE_UI_ACTION_CMD_6A", 0x6A),
]
CMD_MAP = {v: n for n, v in ENUM_VALUES}

FUNCTION_PLATE_COMMENTS = {
    0x005BF740: (
        "[TradeCmdFlow] Handles command tags in trade desk flow.\n"
        "Recognized tags: acce/reje/ForM/enod/koob.\n"
        "Key effects: mode cycle, selection refresh, next-command prompt construction,\n"
        "and selection-rect update for high command IDs."
    ),
    0x00584520: (
        "[TradeCmdFlow] Routes card/offr click events into action command IDs 0x67..0x6A.\n"
        "Branching depends on current bitmap state (bid/offer state pairs) and actionable gate.\n"
        "Also dispatches sound effects and follow-up vtable actions."
    ),
    0x005BF860: (
        "[TradeCmdFlow] Keyboard accept/reject shortcut bridge for trade dialogs.\n"
        "Maps key states to acce/reje controls and queues deferred UI event packet."
    ),
    0x005C04F0: (
        "[TradeCmdFlow] Builds next-trade command object and formatted prompt text.\n"
        "Consumes acce/reje/tool/purc-related control tags and updates related UI states."
    ),
}


TARGETS_FOR_CMD_CONST_ANNOTATION = [0x00584520, 0x005BF740]


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
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType
        from ghidra.program.model.listing import CodeUnit

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        dtm = program.getDataTypeManager()

        tx = program.startTransaction("Annotate trade command/tag flow")
        changed_comments = 0
        changed_plate = 0
        try:
            e = EnumDataType(CategoryPath("/Imperialism"), "ETradeUiActionCommandIdRaw", 4)
            for name, val in ENUM_VALUES:
                e.add(name, val)
            dt = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER)
            print(f"[enum] {dt.getPathName()} values={len(ENUM_VALUES)}")

            for faddr in TARGETS_FOR_CMD_CONST_ANNOTATION:
                fn = fm.getFunctionAt(af.getAddress(f"0x{faddr:08x}"))
                if fn is None:
                    continue
                it = listing.getInstructions(fn.getBody(), True)
                while it.hasNext():
                    ins = it.next()
                    for op_idx in range(ins.getNumOperands()):
                        for obj in ins.getOpObjects(op_idx):
                            val = None
                            if hasattr(obj, "getUnsignedValue"):
                                try:
                                    val = int(obj.getUnsignedValue())
                                except Exception:
                                    val = None
                            if val is None and hasattr(obj, "getValue"):
                                try:
                                    val = int(obj.getValue())
                                except Exception:
                                    val = None
                            if val is None or val not in CMD_MAP:
                                continue
                            c = f"ETradeUiActionCommandIdRaw::{CMD_MAP[val]} (0x{val:x})"
                            old = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
                            if old and c in old:
                                continue
                            new_c = c if not old else f"{old} | {c}"
                            listing.setComment(ins.getAddress(), CodeUnit.EOL_COMMENT, new_c)
                            changed_comments += 1
                            break

            for faddr, comment in FUNCTION_PLATE_COMMENTS.items():
                fn = fm.getFunctionAt(af.getAddress(f"0x{faddr:08x}"))
                if fn is None:
                    continue
                old = fn.getComment() or ""
                if comment in old:
                    continue
                new = comment if not old else f"{old}\n\n{comment}"
                fn.setComment(new)
                changed_plate += 1

            print(f"[comments] eol_changed={changed_comments} plate_changed={changed_plate}")
        finally:
            program.endTransaction(tx, True)

        program.save("annotate trade command/tag flow", None)
        print("[saved]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

