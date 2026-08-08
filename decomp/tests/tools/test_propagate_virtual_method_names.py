#!/usr/bin/env python3
"""Tests for virtual method identity propagation."""

from __future__ import annotations

import unittest

from tools.ghidra.propagate_virtual_method_names import (
    ClassRecord,
    Slot,
    build_propagation_plan,
    find_conflicts,
    parse_method_prototype,
)


class VirtualMethodPropagationTests(unittest.TestCase):
    def test_parse_root_method_prototype(self) -> None:
        parsed = parse_method_prototype("CRuntimeClass* GetRuntimeClass() const")
        self.assertEqual(parsed, ("CRuntimeClass*", []))

        parsed = parse_method_prototype("void Serialize(CArchive& archive)")
        self.assertEqual(parsed, ("void", [("archive", "CArchive&")]))

    def test_tobject_slot0_name_propagates_to_direct_override(self) -> None:
        records = {
            "TBehavior": ClassRecord(
                name="TBehavior",
                base="TObject",
                vtable=0x00648D60,
                slots=(
                    Slot(0, 0x004871C0, "TBehavior::GetTBehaviorClassNamePointer"),
                    Slot(2, 0x00485E90, "TCityTask::GetTTaskClassNamePointer"),
                    Slot(10, 0x00487280, "TBehavior::SetField8", "void __thiscall SetField8(int value)"),
                ),
            )
        }

        plans, surfaces, warnings = build_propagation_plan(records)

        self.assertEqual(warnings, [])
        derived = [p for p in plans if p.cls == "TBehavior"]
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0].new_qualified, "TBehavior::GetRuntimeClass")
        self.assertEqual(derived[0].signature_source, 0x00485E20)
        self.assertEqual(surfaces["TBehavior"][2].identity.method_name, "Serialize")
        self.assertEqual(surfaces["TBehavior"][10].identity.method_name, "SetField8")

    def test_root_seed_repairs_shared_inherited_body_name(self) -> None:
        plans, _surfaces, warnings = build_propagation_plan({})

        self.assertEqual(warnings, [])
        targets = {p.target: p for p in plans if p.cls == "TObject"}
        self.assertEqual(targets[0x00485E90].new_qualified, "TObject::Serialize")
        self.assertEqual(targets[0x00485E90].prototype, "void Serialize(CArchive& archive)")
        self.assertNotIn(0x00412BF0, targets)  # inherited from CObject, not TObject-owned

    def test_grandchild_override_uses_method_introduced_by_parent_tail_slot(self) -> None:
        records = {
            "TBehavior": ClassRecord(
                name="TBehavior",
                base="TObject",
                vtable=0x00648D60,
                slots=(Slot(10, 0x00487280, "TBehavior::SetField8"),),
            ),
            "TDialogBehavior": ClassRecord(
                name="TDialogBehavior",
                base="TBehavior",
                vtable=0x00648DA8,
                slots=(Slot(10, 0x00490000, "TDialogBehavior::OrphanSetter"),),
            ),
        }

        plans, _surfaces, warnings = build_propagation_plan(records)

        self.assertEqual(warnings, [])
        derived = [p for p in plans if p.cls == "TDialogBehavior"]
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0].new_qualified, "TDialogBehavior::SetField8")
        self.assertEqual(derived[0].signature_source, 0x00487280)

    def test_inherited_same_target_does_not_emit_rename(self) -> None:
        records = {
            "TBehavior": ClassRecord(
                name="TBehavior",
                base="TObject",
                vtable=0x00648D60,
                slots=(Slot(7, 0x004798B0, "TCityTask::QueueCityRecruitmentSupportCommandsIfDeficit"),),
            )
        }

        plans, surfaces, warnings = build_propagation_plan(records)

        self.assertEqual(warnings, [])
        self.assertFalse([p for p in plans if p.cls == "TBehavior"])
        self.assertEqual(surfaces["TBehavior"][7].identity.method_name, "Free")

    def test_apply_filter_limits_renames_not_surface_construction(self) -> None:
        records = {
            "TBehavior": ClassRecord(
                name="TBehavior",
                base="TObject",
                vtable=0x00648D60,
                slots=(Slot(10, 0x00487280, "TBehavior::SetField8"),),
            ),
            "TDialogBehavior": ClassRecord(
                name="TDialogBehavior",
                base="TBehavior",
                vtable=0x00648DA8,
                slots=(Slot(10, 0x00490000, "TDialogBehavior::OrphanSetter"),),
            ),
        }

        plans, surfaces, warnings = build_propagation_plan(records, apply_filter={"TBehavior"})

        self.assertEqual(warnings, [])
        self.assertFalse([p for p in plans if p.cls == "TBehavior"])
        self.assertEqual(surfaces["TDialogBehavior"][10].identity.method_name, "SetField8")

    def test_conflict_detects_shared_body_needing_two_class_names(self) -> None:
        records = {
            "TAlpha": ClassRecord(
                name="TAlpha",
                base="TObject",
                vtable=0x00650000,
                slots=(Slot(10, 0x00401000, "TAlpha::AlphaVirtual"),),
            ),
            "TBeta": ClassRecord(
                name="TBeta",
                base="TObject",
                vtable=0x00651000,
                slots=(Slot(10, 0x00402000, "TBeta::BetaVirtual"),),
            ),
            "TAlphaChild": ClassRecord(
                name="TAlphaChild",
                base="TAlpha",
                vtable=0x00652000,
                slots=(Slot(10, 0x00403000, "Shared::Impl"),),
            ),
            "TBetaChild": ClassRecord(
                name="TBetaChild",
                base="TBeta",
                vtable=0x00653000,
                slots=(Slot(10, 0x00403000, "Shared::Impl"),),
            ),
        }

        plans, _surfaces, warnings = build_propagation_plan(records)
        conflicts = find_conflicts(plans)

        self.assertEqual(warnings, [])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].target, 0x00403000)
        self.assertEqual(
            conflicts[0].desired,
            ("TAlphaChild::AlphaVirtual", "TBetaChild::BetaVirtual"),
        )


if __name__ == "__main__":
    unittest.main()
