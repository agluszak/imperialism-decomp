#!/usr/bin/env python3
"""
Create/replace ENationMetricsDispatchSlot enum.

Usage:
  .venv/bin/python new_scripts/create_nation_metrics_dispatch_slot_enum.py
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
        from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler, EnumDataType

        dtm = program.getDataTypeManager()
        cat = CategoryPath("/Imperialism")

        enum_dt = EnumDataType(cat, "ENationMetricsDispatchSlot", 4)
        enum_dt.add("kNationMetricsDispatch_ApplyDiplomacyTransfer_00", 0)
        enum_dt.add("kNationMetricsDispatch_SetMetricCellValue_01", 1)
        enum_dt.add("kNationMetricsDispatch_RunNationUpdatePasses_02", 2)
        enum_dt.add("kNationMetricsDispatch_RunSecondaryNationPreUpdate_03", 3)
        enum_dt.add("kNationMetricsDispatch_BuildSecondaryNationBuckets_04", 4)
        enum_dt.add("kNationMetricsDispatch_BuildEligibleNationBuckets_05", 5)
        enum_dt.add("kNationMetricsDispatch_IsMetricCellNegative_06", 6)
        enum_dt.add("kNationMetricsDispatch_IsMetricCellPositive_07", 7)
        enum_dt.add("kNationMetricsDispatch_AllocateRosterFilteredCollection_08", 8)
        enum_dt.add("kNationMetricsDispatch_SelectPreferredMetricCode_09", 9)
        enum_dt.add("kNationMetricsDispatch_ComputeMetricPowerScale_0A", 10)

        tx = program.startTransaction("Create ENationMetricsDispatchSlot")
        try:
            dtm.addDataType(enum_dt, DataTypeConflictHandler.REPLACE_HANDLER)
        finally:
            program.endTransaction(tx, True)

        program.save("create nation metrics dispatch slot enum", None)
        print("[done] created /Imperialism/ENationMetricsDispatchSlot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
