#!/usr/bin/env python3
"""Tests for vtable-autofix parsing and planning."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.workflow.vtable_autofix import (
    claim_vtable_slots,
    parse_vtable_output,
    plan_for_classes,
)


TCITYTASK_LOG = """\
TCityTask::`vftable' : orig 0x66a9a8, recomp 0x474b10
---
+++
@@ -vtable0x00,16 +vtable0x00,16 @@
vtable0x00 : -(0x5add00 / 0x43ba80)  :  TCityTask::GetTCityTaskClassNamePointer
vtable0x04 : -(0x5add40 / 0x43baa0)  :  TCityTask::DestructTCityTaskAndMaybeFree
           : +(no orig / 0x406780)  :  TCityTask::`scalar deleting destructor'
vtable0x28 : -(0x5adde0 / 0x43bad0)  :  ExecuteDeferredCityOrderCommand
           : +(no orig / 0x4067b0)  :  TCityTask::OrphanLeaf_NoCall_Ins04_005adc30
Vtables found: 1.
Vtables not matching: 1.
"""


TSTATIC_LOG = """\
[WARNING] Recomp vtable is larger than orig vtable for TStaticText::`vftable'
TStaticText::`vftable' : orig 0x64ab58, recomp 0x486d48
---
+++
@@ -vtable0x20,21 +vtable0x20,21 @@
vtable0x48 : -(0x401d61 / 0x42b360)  :  TControl::thunk_ForwardCityDialogParamToChildSlot48
           : +(0x48a380 / 0x40e340)  :  TControl::ForwardCityDialogParamToChildSlot48
vtable0xdc : -(0x406ba9 / no recomp)  :  TView::thunk_NoOpUiLifecycleHook
           : +(0x48ab70 / 0x427ec0)  :  NoOpUiLifecycleHook
Vtables found: 1.
Vtables not matching: 1.
"""


class ParseVtableOutputTests(unittest.TestCase):
    def test_parse_class_findings_and_summary(self) -> None:
        report = parse_vtable_output(TCITYTASK_LOG)
        self.assertEqual(report.classes, ["TCityTask"])
        self.assertEqual(report.found_count, 1)
        self.assertEqual(report.not_matching_count, 1)
        self.assertEqual(len(report.findings), 5)
        self.assertEqual(report.findings[0].slot_byte, 0)
        self.assertEqual(report.findings[1].slot_byte, 4)
        self.assertEqual(report.findings[1].slot_index, 1)
        self.assertEqual(report.findings[2].side, "recomp")

    def test_parse_oversized_and_ilt_findings(self) -> None:
        report = parse_vtable_output(TSTATIC_LOG)
        self.assertEqual(report.oversized, {"TStaticText"})
        ilt_orig = [f.orig for f in report.findings if f.side == "orig"]
        self.assertIn("0x401d61", ilt_orig)
        self.assertIn("0x406ba9", ilt_orig)


class PlanForClassesTests(unittest.TestCase):
    def test_plans_slot_claim_and_scalar_cleanup(self) -> None:
        report = parse_vtable_output(TCITYTASK_LOG)
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "config" / "classes").mkdir(parents=True)
            (root / "config" / "classes" / "TCityTask.yml").write_text("class: TCityTask\n")
            with patch(
                "tools.workflow.vtable_autofix._claimable_manifest_slots",
                return_value=(("0x005add00", "0x005add40"), []),
            ), patch("tools.workflow.vtable_autofix._manifest_slot_kinds", return_value={}):
                plans = plan_for_classes(root, report, ["TCityTask"])
        kinds = [p.kind for p in plans]
        self.assertIn("slot_promotion", kinds)
        self.assertIn("scalar_dtor", kinds)
        slot_plan = next(p for p in plans if p.kind == "slot_promotion")
        self.assertTrue(slot_plan.safe)
        self.assertEqual(slot_plan.addresses, ("0x005add00", "0x005add40"))
        self.assertIn("vtable-autofix TCityTask --write", slot_plan.command or "")

    def test_reports_ilt_base_owned_and_oversized(self) -> None:
        report = parse_vtable_output(TSTATIC_LOG)
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "config" / "classes").mkdir(parents=True)
            (root / "config" / "classes" / "TStaticText.yml").write_text("class: TStaticText\n")
            with patch(
                "tools.workflow.vtable_autofix._claimable_manifest_slots",
                return_value=((), []),
            ), patch(
                "tools.workflow.vtable_autofix._manifest_slot_kinds",
                return_value={0x48 // 4: ("inherited", "TControl"), 0xDC // 4: ("inherited", "TView")},
            ):
                plans = plan_for_classes(root, report, ["TStaticText"])
        kinds = {p.kind for p in plans}
        self.assertIn("ilt_thunk", kinds)
        self.assertIn("base_owned", kinds)
        self.assertIn("oversized_vtable", kinds)
        self.assertFalse(next(p for p in plans if p.kind == "base_owned").safe)
        self.assertFalse(next(p for p in plans if p.kind == "oversized_vtable").safe)


class ClaimVtableSlotsTests(unittest.TestCase):
    def test_claims_slots_with_marker_stubs_without_body_promotion(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "config" / "classes").mkdir(parents=True)
            (root / "include" / "game").mkdir(parents=True)
            (root / "src" / "game").mkdir(parents=True)
            (root / "config" / "symbols.csv").write_text(
                "address|name|size|type|prototype\n"
            )
            (root / "config" / "function_ownership.csv").write_text(
                "address|target_cpp|ownership|note\n"
            )
            (root / "config" / "classes" / "TSample.yml").write_text(
                """\
class: TSample
generated:
  vtable_addr: 0x00660000
  object_size: 0x4
  base: TObject
  ancestry: [TSample, TObject, CObject]
  root: TObject
  slots:
    - {index: 0x00, byte: 0x00, target: 0x00450000, kind: override, is_thunk: false, is_null: false, ghidra_name: TSample::GetTSampleClassNamePointer, size: 6, prototype: "undefined GetTSampleClassNamePointer(void)"}
    - {index: 0x01, byte: 0x04, target: 0x00450040, kind: override, is_thunk: false, is_null: false, ghidra_name: "TSample::'scalar_deleting_destructor'", size: 30, prototype: "undefined 'scalar_deleting_destructor'(byte param_1)"}
curated:
  slots:
    - {index: 0x00, method: GetRuntimeClass, prototype: "CRuntimeClass* GetRuntimeClass(void) const"}
"""
            )
            (root / "include" / "game" / "TSample.h").write_text(
                """\
#pragma once

#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660000
class TSample : public TObject {
public:
  TSample();
};
"""
            )
            (root / "src" / "game" / "TSample.cpp").write_text(
                '#include "game/TSample.h"\n\n'
                "CRuntimeClass* TSample::GetRuntimeClass() const { return 0; }\n\n"
                "TSample::~TSample() {}\n"
            )

            rc = claim_vtable_slots(root, "TSample", write=True)

            self.assertEqual(rc, 0)
            cpp = (root / "src" / "game" / "TSample.cpp").read_text()
            self.assertIn("// FUNCTION: IMPERIALISM 0x00450000", cpp)
            self.assertIn("// SYNTHETIC: IMPERIALISM 0x00450040", cpp)
            self.assertIn("CRuntimeClass* TSample::GetRuntimeClass() const", cpp)
            self.assertIn("TSample::~TSample() {}", cpp)
            self.assertNotIn("Ghidra decompile seed", cpp)
            ownership = (root / "config" / "function_ownership.csv").read_text()
            self.assertIn("450000|src/game/TSample.cpp|manual|marker_sync", ownership)
            self.assertIn("450040|src/game/TSample.cpp|manual|marker_sync", ownership)


if __name__ == "__main__":
    unittest.main()
