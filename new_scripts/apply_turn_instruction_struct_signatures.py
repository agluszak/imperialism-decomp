#!/usr/bin/env python3
"""
Create per-command turn-instruction structs and apply typed handler signatures.

Input CSV columns (from build_tabsenu_schema_loader_bindings.py):
  command,target_va,target_name,arity_primary_strict,is_bound

Usage:
  .venv/bin/python new_scripts/apply_turn_instruction_struct_signatures.py \
    --bindings-csv tmp_decomp/batch419_tabsenu_loader_bindings.csv
"""

from __future__ import annotations

import argparse
import csv
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


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def command_title(cmd: str) -> str:
    cmd = (cmd or "").strip().lower()
    if not cmd:
        return "Unknown"
    return cmd[0].upper() + cmd[1:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--bindings-csv",
        default="tmp_decomp/batch419_tabsenu_loader_bindings.csv",
        help="Loader bindings CSV with command/arity/target columns",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    bindings_csv = Path(args.bindings_csv)
    if not bindings_csv.is_absolute():
        bindings_csv = root / bindings_csv
    if not bindings_csv.exists():
        print(f"missing csv: {bindings_csv}")
        return 1

    rows = list(csv.DictReader(bindings_csv.open("r", encoding="utf-8", newline="")))
    if not rows:
        print(f"empty csv: {bindings_csv}")
        return 1

    plan = []
    for r in rows:
        if (r.get("is_bound") or "").strip() != "1":
            continue
        cmd = (r.get("command") or "").strip().lower()
        va = (r.get("target_va") or "").strip()
        if not cmd or not va:
            continue
        arity_txt = (r.get("arity_primary_strict") or "").strip()
        try:
            arity = int(arity_txt) if arity_txt else 0
        except Exception:
            arity = 0
        plan.append(
            {
                "command": cmd,
                "target_va": va,
                "target_name": (r.get("target_name") or "").strip(),
                "arity": max(0, arity),
            }
        )

    if not plan:
        print("no bound rows to apply")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            EnumDataType,
            PointerDataType,
            StructureDataType,
            UnsignedIntegerDataType,
            VoidDataType,
        )
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        # Prefer existing enum if present; otherwise fallback to uint for token field.
        token_dt = dtm.getDataType("/Imperialism/ETurnInstructionTokenFourCC")
        if token_dt is None:
            token_dt = EnumDataType(
                CategoryPath("/Imperialism"), "ETurnInstructionTokenFourCC", 4
            )
            token_dt = dtm.addDataType(token_dt, DataTypeConflictHandler.KEEP_HANDLER)

        uint_dt = UnsignedIntegerDataType.dataType
        void_ptr_dt = PointerDataType(VoidDataType.dataType)

        tx = program.startTransaction("Apply turn instruction struct signatures")
        created_structs = 0
        updated_sigs = 0
        skipped_funcs = 0
        failed_funcs = 0
        try:
            for item in plan:
                cmd = item["command"]
                target_va = parse_hex(item["target_va"])
                arity = int(item["arity"])

                struct_name = f"STurnInstruction_{command_title(cmd)}"
                struct_path = f"/Imperialism/TurnInstruction/{struct_name}"
                struct_dt = StructureDataType(
                    CategoryPath("/Imperialism/TurnInstruction"), struct_name, 0
                )
                struct_dt.add(token_dt, 4, "eToken", "Instruction token FourCC")
                for i in range(arity):
                    struct_dt.add(
                        uint_dt,
                        4,
                        f"dwArg{i}",
                        f"Command argument {i}",
                    )
                struct_dt = dtm.addDataType(
                    struct_dt, DataTypeConflictHandler.REPLACE_HANDLER
                )
                created_structs += 1

                addr = af.getAddress(f"0x{target_va:08x}")
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    skipped_funcs += 1
                    print(f"[skip] no function at 0x{target_va:08x} for command={cmd}")
                    continue

                try:
                    fn.setCallingConvention("__thiscall")
                    p_this = ParameterImpl("this", void_ptr_dt, program, SourceType.USER_DEFINED)
                    p_instr = ParameterImpl(
                        "pInstruction",
                        PointerDataType(struct_dt),
                        program,
                        SourceType.USER_DEFINED,
                    )
                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [p_this, p_instr],
                    )
                    fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
                    fn.setComment(
                        f"[TurnInstruction] command={cmd} arity={arity} typed via tabsenu loader schema."
                    )
                    updated_sigs += 1
                    print(
                        f"[ok] 0x{target_va:08x} {fn.getName()} :: {struct_path} arity={arity}"
                    )
                except Exception as ex:
                    failed_funcs += 1
                    print(f"[fail] 0x{target_va:08x} command={cmd} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply turn instruction struct signatures", None)
        print(
            f"[done] planned={len(plan)} structs={created_structs} "
            f"sig_ok={updated_sigs} sig_skip={skipped_funcs} sig_fail={failed_funcs}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
