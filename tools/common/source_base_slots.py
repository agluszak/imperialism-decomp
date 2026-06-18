#!/usr/bin/env python3
"""Source-owned base vtable slots for manifest slot reclassification.

When ``dump-manifests`` classifies slots against Ghidra's base vtable, inherited
prefix slots often mislabel as ``new`` because Ghidra uses stale cross-class names
at shared addresses (e.g. slot 0x08 → ``GetTTaskClassNamePointer`` @ ``0x485e90``
is really ``TObject::Serialize``). This module holds the canonical TObject/CObject
prefix table from manual headers and reclassifies manifest slots when the RTTI
base is source-owned.
"""

from __future__ import annotations

from dataclasses import replace

from tools.workflow.class_codegen import (
    ClassifiedSlot,
    Signature,
    norm_addr,
    parse_prototype,
    unqualified,
)

# Sync with include/game/TObject.h, include/game/CObject.h, and FUNCTION markers.
SOURCE_BASE_SLOTS: dict[str, list[tuple[int, str, str, str | None, str]]] = {
    "TObject": [
        (0, "0x00485e20", "TObject::GetRuntimeClass", "CRuntimeClass* GetRuntimeClass() const", "override"),
        (1, "0x00484990", "TObject::`scalar deleting destructor'", None, "scalar_dtor"),
        (2, "0x00485e90", "TObject::Serialize", "void Serialize(CArchive& archive)", "override"),
        (3, "0x00412bf0", "CObject::AssertValid", "void AssertValid() const", "override"),
        (4, "0x00412c10", "CObject::Dump", "void Dump(CDumpContext& dc) const", "override"),
        (5, "0x00485f70", "TObject::WriteTo", "void WriteTo(TStream* stream)", "new"),
        (6, "0x00485f90", "TObject::ReadFrom", "void ReadFrom(TStream* stream)", "new"),
        (7, "0x004798b0", "TObject::Free", "void Free()", "new"),
        (8, "0x004798d0", "TObject::ShallowClone", "TObject* ShallowClone()", "new"),
        (9, "0x00415ce0", "TObject::ShallowFree", "TObject* ShallowFree()", "new"),
    ],
    "CObject": [
        (0, "0x00606fba", "CObject::GetRuntimeClass", "CRuntimeClass* GetRuntimeClass() const", "override"),
        (1, "0x00415f00", "CObject::`scalar deleting destructor'", None, "scalar_dtor"),
        (2, "0x00412bd0", "CObject::Serialize", "void Serialize(CArchive& archive)", "override"),
        (3, "0x00412bf0", "CObject::AssertValid", "void AssertValid() const", "override"),
        (4, "0x00412c10", "CObject::Dump", "void Dump(CDumpContext& dc) const", "override"),
    ],
}


def source_base_slot_records(base: str) -> list[ClassifiedSlot]:
    out: list[ClassifiedSlot] = []
    for idx, target, qualified, proto, kind in SOURCE_BASE_SLOTS.get(base, []):
        fallback = unqualified(qualified)
        sig = parse_prototype(proto, fallback) if proto else None
        out.append(
            ClassifiedSlot(
                index=idx,
                byte_offset=idx * 4,
                slot_label=f"0x{idx * 4:02x}",
                target_addr=norm_addr(target),
                kind=kind,
                sig=sig,
                qualified_name=qualified,
                size=0,
                prototype=proto,
                decompiled_c=None,
                base_target=None,
            )
        )
    return out


def apply_source_base_slots(slots: list[ClassifiedSlot], base: str) -> list[ClassifiedSlot]:
    """Correct manifest slot kinds/signatures when the base is source-owned only."""
    base_slots = {s.index: s for s in source_base_slot_records(base)}
    if not base_slots:
        return slots

    out: list[ClassifiedSlot] = []
    for slot in slots:
        base_slot = base_slots.get(slot.index)
        if base_slot is None or slot.kind in ("null", "ilt_thunk"):
            out.append(slot)
            continue

        if norm_addr(slot.target_addr) == base_slot.target_addr:
            out.append(
                replace(
                    slot,
                    kind="inherited",
                    sig=None,
                    qualified_name=base_slot.qualified_name,
                    base_target=base_slot.target_addr,
                    dtor_suspect=False,
                )
            )
            continue

        if base_slot.kind == "scalar_dtor":
            out.append(
                replace(
                    slot,
                    kind="scalar_dtor",
                    sig=None,
                    qualified_name=f"{slot.qualified_name or ''} (verify scalar deleting destructor)",
                    base_target=base_slot.target_addr,
                    dtor_suspect=False,
                )
            )
            continue

        assert base_slot.sig is not None
        out.append(
            replace(
                slot,
                kind="override",
                sig=base_slot.sig,
                qualified_name=base_slot.qualified_name,
                base_target=base_slot.target_addr,
                dtor_suspect=False,
            )
        )
    return out


def source_base_scaffold_issues(cls: str, base: str, slot_indices: list[int]) -> list[str]:
    base_slots = source_base_slot_records(base)
    if not base_slots or not slot_indices:
        return []
    max_index = max(slot_indices)
    max_base_index = max(s.index for s in base_slots)
    if max_index >= max_base_index:
        return []
    return [
        f"{cls} manifest has slots through 0x{max_index:02x}, but source-modeled "
        f"{base} reaches slot 0x{max_base_index:02x}; likely an alias/nonstandard table"
    ]
