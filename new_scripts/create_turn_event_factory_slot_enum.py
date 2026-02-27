#!/usr/bin/env python3
"""
Create/update ETurnEventFactorySlotId enum from named slot handlers.

Scans function names like:
  HandleTurnEventDialogFactorySlot70
  HandleTurnEventDialogFactorySlotF8

and creates/updates:
  /Imperialism/ETurnEventFactorySlotId
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
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--enum-path",
        default="/Imperialism/ETurnEventFactorySlotId",
        help="Destination enum full path",
    )
    ap.add_argument(
        "--name-regex",
        default=r"^HandleTurnEventDialogFactorySlot([0-9A-Fa-f]{2})$",
        help="Regex with one capture group for slot hex byte",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    slot_re = re.compile(args.name_regex)
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import CategoryPath, EnumDataType

        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        slots: dict[int, str] = {}
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            m = slot_re.match(f.getName())
            if not m:
                continue
            v = int(m.group(1), 16)
            label = f"TURN_EVENT_FACTORY_SLOT_{v:02X}"
            slots[v] = label

        if not slots:
            print("[skip] no matching slot handlers found")
            return 0

        enum_path = args.enum_path
        parts = [p for p in enum_path.split("/") if p]
        enum_name = parts[-1]
        cat_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"

        existing = dtm.getDataType(enum_path)
        tx = program.startTransaction("Create/update ETurnEventFactorySlotId")
        try:
            if existing is None:
                e = EnumDataType(CategoryPath(cat_path), enum_name, 4)
                for v, lbl in sorted(slots.items()):
                    e.add(lbl, v)
                dtm.addDataType(e, None)
                print(f"[enum] created {enum_path} entries={len(slots)}")
            else:
                e = existing
                added = 0
                for v, lbl in sorted(slots.items()):
                    if e.getName(v) is None:
                        e.add(lbl, v)
                        added += 1
                print(
                    f"[enum] updated {enum_path} existing_entries={e.getCount()} added={added}"
                )
        finally:
            program.endTransaction(tx, True)

        program.save("create/update turn-event factory slot enum", None)
        for v, lbl in sorted(slots.items()):
            print(f"{lbl}={v}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
