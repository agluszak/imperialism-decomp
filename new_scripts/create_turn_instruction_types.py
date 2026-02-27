#!/usr/bin/env python3
"""
Create turn-instruction token enum and type core dispatch tables.

Inputs:
  - tmp_decomp/scenario_dispatch_token_handler_map_batch55.csv

Applies:
  - /Imperialism/ETurnInstructionTokenFourCC enum (size 4)
  - enum array at 0x00662978 (27 entries)
  - pointer array at 0x00698b50 (27 entries)
  - stable labels/comments for both tables

Usage:
  .venv/bin/python new_scripts/create_turn_instruction_types.py
"""

from __future__ import annotations

import csv
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"
TOKEN_MAP_CSV = Path("tmp_decomp/scenario_dispatch_token_handler_map_batch55.csv")
TOKEN_TABLE_ADDR = 0x00662978
HANDLER_TABLE_ADDR = 0x00698B50
ENTRY_COUNT = 27


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def encode_fourcc_be(text4: str) -> int:
    b = text4.encode("ascii", errors="strict")
    if len(b) != 4:
        raise ValueError(f"expected 4 chars, got {text4!r}")
    return int.from_bytes(b, byteorder="big", signed=False)


def sanitize_enum_member(command: str) -> str:
    out = []
    for ch in command.upper():
        if ("A" <= ch <= "Z") or ("0" <= ch <= "9"):
            out.append(ch)
        else:
            out.append("_")
    return "TURN_TOKEN_" + "".join(out)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    token_map_path = root / TOKEN_MAP_CSV
    if not token_map_path.exists():
        print(f"[error] missing token map csv: {token_map_path}")
        return 1

    rows = list(csv.DictReader(token_map_path.open("r", encoding="utf-8", newline="")))
    if not rows:
        print(f"[error] empty token map csv: {token_map_path}")
        return 1

    parsed = []
    for r in rows:
        idx_txt = (r.get("index") or "").strip()
        cmd = (r.get("token_decoded") or r.get("token") or "").strip().lower()
        token_raw = (r.get("token_raw") or "").strip().lower()
        if not idx_txt.isdigit() or not cmd or len(cmd) != 4:
            continue
        parsed.append((int(idx_txt), cmd, token_raw, r))
    parsed.sort(key=lambda t: t[0])

    if len(parsed) < ENTRY_COUNT:
        print(f"[warn] parsed {len(parsed)} entries (expected {ENTRY_COUNT})")

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import (
            ArrayDataType,
            CategoryPath,
            DataTypeConflictHandler,
            EnumDataType,
            FunctionDefinitionDataType,
            GenericCallingConvention,
            ParameterDefinitionImpl,
            PointerDataType,
            UnsignedIntegerDataType,
            VoidDataType,
        )
        from ghidra.program.model.symbol import SourceType

        dtm = program.getDataTypeManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        st = program.getSymbolTable()

        token_addr = af.getAddress(f"0x{TOKEN_TABLE_ADDR:08x}")
        handler_addr = af.getAddress(f"0x{HANDLER_TABLE_ADDR:08x}")

        tx = program.startTransaction("Create turn-instruction types")
        try:
            token_enum = EnumDataType(CategoryPath("/Imperialism"), "ETurnInstructionTokenFourCC", 4)
            index_enum = EnumDataType(CategoryPath("/Imperialism"), "ETurnInstructionDispatchIndex", 4)
            for idx, cmd, _token_raw, _r in parsed:
                member = sanitize_enum_member(cmd)
                value = encode_fourcc_be(cmd)
                try:
                    token_enum.add(member, value)
                except Exception:
                    token_enum.add(f"{member}_{idx}", value)
                try:
                    index_enum.add(member.replace("TURN_TOKEN_", "TURN_INSTR_"), idx)
                except Exception:
                    index_enum.add(f"TURN_INSTR_{cmd.upper()}_{idx}", idx)

            enum_dt = dtm.addDataType(token_enum, DataTypeConflictHandler.REPLACE_HANDLER)
            index_enum_dt = dtm.addDataType(index_enum, DataTypeConflictHandler.REPLACE_HANDLER)

            handler_fdef = FunctionDefinitionDataType(
                CategoryPath("/Imperialism"), "TTurnInstructionHandlerProc"
            )
            handler_fdef.setReturnType(VoidDataType.dataType)
            handler_fdef.setGenericCallingConvention(GenericCallingConvention.thiscall)
            handler_fdef.setArguments(
                [
                    ParameterDefinitionImpl(
                        "pStreamCursor",
                        PointerDataType(UnsignedIntegerDataType.dataType),
                        "Pointer to current turn-instruction stream cursor",
                    )
                ]
            )
            handler_fdef_dt = dtm.addDataType(
                handler_fdef, DataTypeConflictHandler.REPLACE_HANDLER
            )
            token_arr_dt = ArrayDataType(enum_dt, ENTRY_COUNT, enum_dt.getLength())
            handler_arr_dt = ArrayDataType(PointerDataType(handler_fdef_dt), ENTRY_COUNT, 4)

            token_end = token_addr.add(token_arr_dt.getLength() - 1)
            handler_end = handler_addr.add(handler_arr_dt.getLength() - 1)

            listing.clearCodeUnits(token_addr, token_end, False)
            listing.createData(token_addr, token_arr_dt)
            listing.clearCodeUnits(handler_addr, handler_end, False)
            listing.createData(handler_addr, handler_arr_dt)

            token_lbl = "g_aeTurnInstructionTokenFourCCByIndex"
            handler_lbl = "g_apfnTurnInstructionHandlerByIndex"

            ps = st.getPrimarySymbol(token_addr)
            if ps is None:
                s = st.createLabel(token_addr, token_lbl, SourceType.USER_DEFINED)
                s.setPrimary()
            elif ps.getName() != token_lbl:
                ps.setName(token_lbl, SourceType.USER_DEFINED)

            ps = st.getPrimarySymbol(handler_addr)
            if ps is None:
                s = st.createLabel(handler_addr, handler_lbl, SourceType.USER_DEFINED)
                s.setPrimary()
            elif ps.getName() != handler_lbl:
                ps.setName(handler_lbl, SourceType.USER_DEFINED)

            token_cu = listing.getCodeUnitAt(token_addr)
            if token_cu is not None:
                token_cu.setComment(
                    token_cu.EOL_COMMENT,
                    "Turn-instruction token FourCC values indexed by dispatch index (0..26).",
                )
            handler_cu = listing.getCodeUnitAt(handler_addr)
            if handler_cu is not None:
                handler_cu.setComment(
                    handler_cu.EOL_COMMENT,
                    "Function-pointer table for turn-instruction handlers by dispatch index (0..26).",
                )
        finally:
            program.endTransaction(tx, True)

        program.save("create turn instruction types", None)
        print(f"[done] enum={enum_dt.getPathName()} entries={len(parsed)}")
        print(f"[done] enum={index_enum_dt.getPathName()} entries={len(parsed)}")
        print(f"[done] fdef={handler_fdef_dt.getPathName()}")
        print(f"[typed] 0x{TOKEN_TABLE_ADDR:08x} as {token_arr_dt.getName()}")
        print(f"[typed] 0x{HANDLER_TABLE_ADDR:08x} as {handler_arr_dt.getName()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
