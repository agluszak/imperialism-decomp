#!/usr/bin/env python3
"""
Create/update turn-event factory slot enum + packet struct and apply core signatures.

Applies:
  - /imperialism/ETurnEventFactorySlotId
  - /imperialism/TurnEvent/STurnEventFactoryPacket
  - signatures for Build/Dispatch turn-event factory packet helpers + thunks
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.datatypes import (
    project_category_path,
    project_datatype_path,
    resolve_datatype_by_path_or_legacy_aliases,
)
from imperialism_re.core.ghidra_session import open_program


SLOT_VALUES = (
    0x70,
    0x74,
    0x78,
    0x7C,
    0x80,
    0xB4,
    0xB8,
    0xD0,
    0xD8,
    0xE4,
    0xE8,
    0xEC,
    0xF0,
    0xF4,
    0xF8,
)


def _build_slot_member_name(value: int) -> str:
    return f"TURN_EVENT_FACTORY_SLOT_{value:02X}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-fn", default="0x0048cf10")
    ap.add_argument("--build-thunk", default="0x00408d46")
    ap.add_argument("--dispatch-fn", default="0x0048cfd0")
    ap.add_argument("--dispatch-thunk", default="0x00404593")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        from ghidra.program.model.data import (
            CategoryPath,
            DataTypeConflictHandler,
            EnumDataType,
            PointerDataType,
            StructureDataType,
            UnsignedIntegerDataType,
            UnsignedShortDataType,
            VoidDataType,
        )
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        dtm = program.getDataTypeManager()

        tx = program.startTransaction("Create turn-event factory types")
        try:
            enum_name = "ETurnEventFactorySlotId"
            enum_dt = EnumDataType(CategoryPath(project_category_path()), enum_name, 2)
            for v in SLOT_VALUES:
                enum_dt.add(_build_slot_member_name(v), v)
            enum_dt = dtm.addDataType(enum_dt, DataTypeConflictHandler.REPLACE_HANDLER)

            packet_category = project_category_path("TurnEvent")
            packet_name = "STurnEventFactoryPacket"
            packet = StructureDataType(CategoryPath(packet_category), packet_name, 0)

            u32 = UnsignedIntegerDataType.dataType
            u16 = UnsignedShortDataType.dataType
            packet_ptr = PointerDataType(packet)

            shared_ref_dt = resolve_datatype_by_path_or_legacy_aliases(
                dtm, project_datatype_path("STSharedStringRef", "String")
            )
            if shared_ref_dt is None:
                shared_ref_dt = u32

            packet.add(u32, 4, "dwVtableOrType", None)  # +0x00
            packet.add(u32, 4, "dwMode04", None)  # +0x04
            packet.add(u32, 4, "dwFlags08", None)  # +0x08
            packet.add(packet_ptr, 4, "pSourcePacket0C", None)  # +0x0c
            packet.add(u32, 4, "dwUnknown10", None)  # +0x10
            packet.add(u32, 4, "dwUnknown14", None)  # +0x14
            packet.add(u32, 4, "dwUnknown18", None)  # +0x18
            packet.add(u32, 4, "dwTag1C", None)  # +0x1c
            packet.add(u32, 4, "dwUnknown20", None)  # +0x20
            packet.add(u32, 4, "dwScratch24", None)  # +0x24
            packet.add(u32, 4, "dwScratch28", None)  # +0x28
            packet.add(u32, 4, "dwUnknown2C", None)  # +0x2c
            packet.add(u32, 4, "dwUnknown30", None)  # +0x30
            packet.add(u32, 4, "dwPayload34", None)  # +0x34
            packet.add(u32, 4, "dwPayload38", None)  # +0x38
            packet.add(u32, 4, "dwUnknown3C", None)  # +0x3c
            packet.add(u32, 4, "dwDispatchArg40", None)  # +0x40
            packet.add(u32, 4, "dwUnknown44", None)  # +0x44
            packet.add(u32, 4, "dwUnknown48", None)  # +0x48
            packet.add(u32, 4, "pOwnerWindowCtx4C", None)  # +0x4c
            packet.add(u32, 4, "dwOwnerCtxMirror50", None)  # +0x50
            packet.add(u32, 4, "dwUnknown54", None)  # +0x54
            packet.add(u32, 4, "dwUnknown58", None)  # +0x58
            packet.add(u32, 4, "dwUnknown5C", None)  # +0x5c
            packet.add(enum_dt, 2, "eFactorySlot60", None)  # +0x60
            packet.add(u16, 2, "wPad62", None)  # +0x62
            packet.add(u32, 4, "dwPayload64", None)  # +0x64
            packet.add(u32, 4, "dwPayload68", None)  # +0x68
            packet.add(shared_ref_dt, max(1, int(shared_ref_dt.getLength())), "sharedString6C", None)  # +0x6c
            packet.add(u16, 2, "wPayload70", None)  # +0x70
            packet.add(u16, 2, "wPad72", None)  # +0x72

            packet_dt = dtm.addDataType(packet, DataTypeConflictHandler.REPLACE_HANDLER)
            packet_ptr_dt = PointerDataType(packet_dt)
            slot_enum_dt = resolve_datatype_by_path_or_legacy_aliases(
                dtm, project_datatype_path(enum_name)
            )
            if slot_enum_dt is None:
                slot_enum_dt = enum_dt
            slot_param_dt = slot_enum_dt

            def _apply_signature(
                addr_txt: str,
                cc: str,
                return_dt,
                params: list[tuple[str, object]],
            ) -> bool:
                addr = af.getAddress(f"0x{int(addr_txt, 0):08x}")
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    print(f"[skip] missing function at {addr_txt}")
                    return False
                try:
                    fn.setCallingConvention(cc)
                    p_objs = [
                        ParameterImpl(name, dt, program, SourceType.USER_DEFINED)
                        for name, dt in params
                    ]
                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        p_objs,
                    )
                    fn.setReturnType(return_dt, SourceType.USER_DEFINED)
                    return True
                except Exception as ex:
                    print(f"[fail] {addr_txt} {fn.getName()} err={ex}")
                    return False

            u32_ptr_dt = PointerDataType(u32)
            shared_ref_ptr_dt = PointerDataType(shared_ref_dt)
            void_dt = VoidDataType.dataType

            sig_ok = 0
            for addr_txt in (args.build_fn, args.build_thunk):
                if _apply_signature(
                    addr_txt,
                    "__thiscall",
                    void_dt,
                    [
                        ("this", packet_ptr_dt),
                        ("dwDispatchArg40", u32),
                        ("pSourcePacket0C", packet_ptr_dt),
                        ("eFactorySlot60", slot_param_dt),
                        ("pPayloadPair64_68", u32_ptr_dt),
                        ("pSharedString6C", shared_ref_ptr_dt),
                        ("wPayload70", u16),
                    ],
                ):
                    sig_ok += 1

            for addr_txt in (args.dispatch_fn, args.dispatch_thunk):
                if _apply_signature(
                    addr_txt,
                    "__fastcall",
                    void_dt,
                    [("pEventPacket", packet_ptr_dt)],
                ):
                    sig_ok += 1
        finally:
            program.endTransaction(tx, True)

        program.save("create turn-event factory types", None)
        print(f"[done] enum={enum_dt.getPathName()} entries={len(SLOT_VALUES)}")
        print(f"[done] struct={packet_dt.getPathName()} size=0x{int(packet_dt.getLength()):x}")
        print(f"[done] signatures_applied={sig_ok}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
