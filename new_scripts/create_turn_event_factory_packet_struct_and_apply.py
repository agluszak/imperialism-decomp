#!/usr/bin/env python3
"""
Create STurnEventFactoryPacket and apply typed factory packet signatures.

Usage:
  .venv/bin/python new_scripts/create_turn_event_factory_packet_struct_and_apply.py
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
        from ghidra.program.model.data import (
            ArrayDataType,
            ByteDataType,
            CategoryPath,
            DataTypeConflictHandler,
            PointerDataType,
            ShortDataType,
            StructureDataType,
            UnsignedIntegerDataType,
            UnsignedShortDataType,
            VoidDataType,
        )
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        dtm = program.getDataTypeManager()
        fm = program.getFunctionManager()

        uint_dt = UnsignedIntegerDataType.dataType
        ushort_dt = UnsignedShortDataType.dataType
        short_dt = ShortDataType.dataType
        void_ptr_dt = PointerDataType(VoidDataType.dataType)
        byte_arr = lambda n: ArrayDataType(ByteDataType.dataType, n, 1)  # noqa: E731

        tx = program.startTransaction(
            "Create STurnEventFactoryPacket and apply signatures"
        )
        try:
            # Shared-string payload in packet records is manipulated via
            # StringShared::AssignFromPtr(dst=&packet+0x6c, src=param).
            # Keep a conservative 4-byte wrapper type for readability.
            sref = StructureDataType(
                CategoryPath("/Imperialism/String"),
                "STSharedStringRef",
                0,
            )
            sref.add(void_ptr_dt, 4, "pSharedData", "Shared string payload pointer")
            sref = dtm.addDataType(sref, DataTypeConflictHandler.REPLACE_HANDLER)
            p_sref = PointerDataType(sref)

            struct_name = "STurnEventFactoryPacket"
            st = StructureDataType(CategoryPath("/Imperialism/TurnEvent"), struct_name, 0)
            st.add(uint_dt, 4, "dwVtableOrType", "Packet/object header")
            st.add(uint_dt, 4, "dwMode04", "Builder sets to 1")
            st.add(uint_dt, 4, "dwFlags08", "Builder sets to 1")
            st.add(void_ptr_dt, 4, "pSourcePacket0C", "Pointer to source packet")
            st.add(byte_arr(0x10), 0x10, "abUnknown10", "Reserved/unknown")
            st.add(uint_dt, 4, "dwTag1C", "Tag initialized to 0x20202020")
            st.add(uint_dt, 4, "dwUnknown20", "Reserved/unknown")
            st.add(void_ptr_dt, 4, "pFactoryData24", "Factory context pointer")
            st.add(void_ptr_dt, 4, "pFactoryData28", "Factory context pointer")
            st.add(byte_arr(8), 8, "abUnknown2C", "Reserved/unknown")
            st.add(uint_dt, 4, "dwPayload34", "Source packet +0x34")
            st.add(uint_dt, 4, "dwPayload38", "Source packet +0x38")
            st.add(uint_dt, 4, "dwUnknown3C", "Reserved/unknown")
            st.add(uint_dt, 4, "dwDispatchArg40", "Dispatch auxiliary argument")
            st.add(byte_arr(0x0C), 0x0C, "abUnknown44", "Reserved/unknown")
            st.add(uint_dt, 4, "dwOwnerWindowCtx50", "Owner/window context")
            st.add(byte_arr(0x0C), 0x0C, "abUnknown54", "Reserved/unknown")
            st.add(short_dt, 2, "eFactorySlot60", "ETurnEventFactorySlotId payload")
            st.add(ushort_dt, 2, "wPad62", "Padding")
            st.add(uint_dt, 4, "dwPayload64", "Aux payload")
            st.add(uint_dt, 4, "dwPayload68", "Aux payload")
            st.add(sref, 4, "sharedString6C", "Inline shared-string ref payload")
            st.add(ushort_dt, 2, "wPayload70", "Aux payload")

            st = dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
            p_st = PointerDataType(st)
            p_uint = PointerDataType(uint_dt)

            # Tighten recursive packet linkage: source packet is the same packet shape.
            try:
                st.replaceAtOffset(
                    0x0C,
                    p_st,
                    4,
                    "pSourcePacket0C",
                    "Pointer to source STurnEventFactoryPacket",
                )
            except Exception as ex:
                print(f"[warn] could not replace pSourcePacket0C field type: {ex}")

            try:
                st.replaceAtOffset(
                    0x6C,
                    sref,
                    4,
                    "sharedString6C",
                    "Inline STSharedStringRef payload for StringShared::AssignFromPtr",
                )
            except Exception as ex:
                print(f"[warn] could not replace sharedString6C field type: {ex}")

            # Dispatch path: packet pointer only.
            dispatch_addr = af.getAddress("0x0048cfd0")
            dispatch_fn = fm.getFunctionAt(dispatch_addr)
            if dispatch_fn is None:
                print("[fail] missing function at 0x0048cfd0")
            else:
                dispatch_fn.setCallingConvention("__fastcall")
                dispatch_p_packet = ParameterImpl(
                    "pEventPacket", p_st, program, SourceType.USER_DEFINED
                )
                dispatch_fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    [dispatch_p_packet],
                )
                dispatch_fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
                dispatch_fn.setComment(
                    "[Typed] Uses STurnEventFactoryPacket::eFactorySlot60 "
                    "(ETurnEventFactorySlotId) for dispatch."
                )
                print(
                    f"[ok] {dispatch_fn.getEntryPoint()} {dispatch_fn.getName()} :: "
                    f"{dispatch_fn.getSignature()}"
                )

            # Builder path: thiscall packet-construction routine with stable argument roles.
            build_addr = af.getAddress("0x0048cf10")
            build_fn = fm.getFunctionAt(build_addr)
            if build_fn is None:
                print("[fail] missing function at 0x0048cf10")
            else:
                build_fn.setCallingConvention("__thiscall")
                build_params = [
                    ParameterImpl(
                        "dwDispatchArg40",
                        uint_dt,
                        program,
                        SourceType.USER_DEFINED,
                    ),
                    ParameterImpl(
                        "pSourcePacket0C",
                        p_st,
                        program,
                        SourceType.USER_DEFINED,
                    ),
                    ParameterImpl(
                        "eFactorySlot60",
                        short_dt,
                        program,
                        SourceType.USER_DEFINED,
                    ),
                    ParameterImpl(
                        "pPayloadPair64_68",
                        p_uint,
                        program,
                        SourceType.USER_DEFINED,
                    ),
                    ParameterImpl(
                        "pSharedString6C",
                        p_sref,
                        program,
                        SourceType.USER_DEFINED,
                    ),
                    ParameterImpl(
                        "wPayload70",
                        ushort_dt,
                        program,
                        SourceType.USER_DEFINED,
                    ),
                ]
                build_fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    build_params,
                )
                build_fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
                build_fn.setComment(
                    "[Typed] this=STurnEventFactoryPacket*. Builds packet fields "
                    "including pSourcePacket0C:STurnEventFactoryPacket*, "
                    "eFactorySlot60 and dispatch payload (+0x64/+0x68)."
                )
                print(
                    f"[ok] {build_fn.getEntryPoint()} {build_fn.getName()} :: "
                    f"{build_fn.getSignature()}"
                )

            # Keep direct thunk wrappers in sync with typed targets.
            thunk_specs = [
                ("0x00408d46", "__thiscall", "BuildTurnEventFactoryPacket"),
                (
                    "0x00404593",
                    "__fastcall",
                    "DispatchTurnEventPacketThroughDialogFactory",
                ),
            ]
            for addr_txt, cc_name, thunk_target in thunk_specs:
                thunk_fn = fm.getFunctionAt(af.getAddress(addr_txt))
                if thunk_fn is None:
                    print(f"[skip] missing thunk at {addr_txt}")
                    continue
                thunk_fn.setCallingConvention(cc_name)
                if thunk_target == "BuildTurnEventFactoryPacket":
                    thunk_fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        build_params,
                    )
                else:
                    thunk_fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        [dispatch_p_packet],
                    )
                thunk_fn.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED)
                thunk_fn.setComment(
                    "[Typed] Direct thunk kept signature-aligned with target "
                    f"{thunk_target}."
                )
                print(
                    f"[ok] {thunk_fn.getEntryPoint()} {thunk_fn.getName()} :: "
                    f"{thunk_fn.getSignature()}"
                )

        finally:
            program.endTransaction(tx, True)

        program.save("create STurnEventFactoryPacket and apply signatures", None)
        print(f"[done] struct=/Imperialism/TurnEvent/STurnEventFactoryPacket")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
