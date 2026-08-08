#!/usr/bin/env python3
"""Tests for vtable-autofix parsing and planning."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.workflow.vtable_autofix import (
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
           : +(0x48ab70 / 0x427ec0)  :  DoPostCreate
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
    def test_plans_scalar_dtor_cleanup(self) -> None:
        report = parse_vtable_output(TCITYTASK_LOG)
        with TemporaryDirectory() as td:
            root = Path(td)
            plans = plan_for_classes(root, report, ["TCityTask"])
        kinds = [p.kind for p in plans]
        self.assertIn("scalar_dtor", kinds)
        dtor_plan = next(p for p in plans if p.kind == "scalar_dtor")
        self.assertTrue(dtor_plan.safe)
        self.assertEqual(dtor_plan.command, "just correct-scalar-dtors")

    def test_reports_ilt_thunk_and_oversized(self) -> None:
        report = parse_vtable_output(TSTATIC_LOG)
        with TemporaryDirectory() as td:
            root = Path(td)
            plans = plan_for_classes(root, report, ["TStaticText"])
        kinds = {p.kind for p in plans}
        self.assertIn("ilt_thunk", kinds)
        self.assertIn("oversized_vtable", kinds)
        self.assertFalse(next(p for p in plans if p.kind == "oversized_vtable").safe)


if __name__ == "__main__":
    unittest.main()
