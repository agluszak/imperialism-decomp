"""Regression fixtures for the vtable ABI audit.

Encodes the corrected TMapMaker evidence (the incident that motivated the
audit): seven slot declarations had been copied from unrelated TEventHandler/
TView methods at the same slot ordinals while `just vtable TMapMaker` stayed at
100%. Each fixture pins binary ground truth (RET kind/imm, ECX use, caller
facts where relevant) and asserts that the FORMER declaration is rejected as a
proven conflict while the CURRENT declaration is accepted.

Also covers: TOffLimitsPicture slot 0x73 (small one-arg fixture), a TArmyMgr
slot corrected from zero to two args, the TMapMaker null-tail/adjacent
stretch-table vtable-extent case, and the generator's refusal to emit
poison-pill prototypes.
"""

from __future__ import annotations

import unittest

from tools.workflow.vtable_abi_audit import (
    Decl,
    arg_stack_dwords,
    classify_slot,
    parse_definition_head,
    ret_width_class,
)
from tools.workflow.vtable_extent_rules import extent_decision


def member(addr: int, cls: str, name: str, ret: str | None, args: str) -> Decl:
    return Decl(
        addr=addr, file="src/game/X.cpp", line=1, ret=ret, cls=cls, name=name,
        args=args, conv="", origin="manual",
    )


def facts(
    ret_kind: str,
    ret_imm: int,
    ecx: str = "ecx_this",
    push_counts: dict | None = None,
    ret_use: dict | None = None,
) -> dict:
    return {
        "name": "x",
        "size": 100,
        "cc": "__thiscall",
        "ghidra_params": 0,
        "ghidra_proto": "undefined x()",
        "ret_kind": ret_kind,
        "ret_imm": ret_imm,
        "ecx": ecx,
        "max_stack_arg_read": None,
        "callers": {
            "sites": sum((push_counts or {}).values()),
            "analyzed": sum((push_counts or {}).values()),
            "push_counts": push_counts or {},
            "cleanup_bytes": {},
            "ret_use": ret_use or {},
            "ecx_sources": {},
            "examples": [],
        },
    }


class TestTMapMakerFixtures(unittest.TestCase):
    """The seven corrected TMapMaker slots: former decls rejected, current accepted."""

    def check(self, fact: dict, old: Decl, new: Decl) -> None:
        old_finding = classify_slot(old, fact, None)
        new_finding = classify_slot(new, fact, None)
        self.assertEqual(
            old_finding.verdict, "proven_conflict",
            f"former declaration must be rejected: {old_finding.reasons}",
        )
        self.assertEqual(
            new_finding.verdict, "strong_support",
            f"current declaration must be accepted: {new_finding.reasons}",
        )

    def test_slot_0x30_assign_region_class(self):
        # 0x527040: RET 0x10 (4 stack dwords); the 0x526c20 caller pushes 4 ints.
        fact = facts("imm", 0x10, push_counts={"4": 2}, ret_use={"eax": 2})
        old = member(0x527040, "TMapMaker", "QueryStepValue", "TEventHandler*", "")
        new = member(
            0x527040, "TMapMaker", "AssignRegionClassToCellAndNeighbors",
            "int", "int cellIndex, int mode, int classIndex, int retryBudget",
        )
        self.check(fact, old, new)

    def test_slot_0x34_merge_majors(self):
        # 0x527300: RET 0x8 (2 stack dwords); caller tests AL.
        fact = facts("imm", 0x8, ret_use={"al": 2})
        old = member(
            0x527300, "TMapMaker", "DispatchQueuedUiCommandAndRelease", "void", "void* command"
        )
        new = member(
            0x527300, "TMapMaker", "TryMergeRegionGroupWithNeighborsRestrictedToMajors",
            "char", "int cellIndex, int classIndex",
        )
        self.check(fact, old, new)

    def test_slot_0x40_merge_general(self):
        # 0x5274d0: RET 0x8 (2 stack dwords).
        fact = facts("imm", 0x8, ret_use={"al": 2})
        old = member(
            0x5274d0, "TMapMaker", "DispatchEvent", "char",
            "int code, TEventHandler* handler, TEvent* event",
        )
        new = member(
            0x5274d0, "TMapMaker", "TryMergeRegionGroupWithNeighbors",
            "char", "int cellIndex, int classIndex",
        )
        self.check(fact, old, new)

    def test_slot_0x44_smoothing_pass(self):
        # 0x528e50: bare RET — zero stack args.
        fact = facts("plain", 0)
        old = member(0x528e50, "TMapMaker", "vmethod_0017", "void", "int param")
        new = member(
            0x528e50, "TMapMaker", "SmoothCityRegionOwnershipByNeighborSampling", "void", ""
        )
        self.check(fact, old, new)

    def test_slot_0x48_forward_param(self):
        # 0x5283c0: RET 0xc (3 stack dwords).
        fact = facts("imm", 0xC, ret_use={"eax": 2})
        old = member(0x5283C0, "TMapMaker", "ForwardParam", "void", "int param")
        new = member(
            0x5283C0, "TMapMaker", "ForwardParam", "int",
            "int tileIndex, int retryBudget, int featureType",
        )
        self.check(fact, old, new)

    def test_slot_0x4c_do_idle(self):
        # 0x528670: bare RET — zero stack args.
        fact = facts("plain", 0)
        old = member(0x528670, "TMapMaker", "DoIdle", "char", "int action")
        new = member(0x528670, "TMapMaker", "DoIdle", "char", "")
        self.check(fact, old, new)

    def test_slot_0x58_place_city_marker(self):
        # 0x528140: RET 0xc (3 stack dwords; self-recursive call site pushes 3).
        fact = facts("imm", 0xC, push_counts={"3": 2}, ret_use={"eax": 2})
        old = member(0x528140, "TMapMaker", "OwnerPanel", "TView*", "")
        new = member(
            0x528140, "TMapMaker", "PlaceCityMarkerAndSpreadNeighbors", "int",
            "int tileIndex, int retryBudget, char markerVariant",
        )
        self.check(fact, old, new)


class TestSmallFixtures(unittest.TestCase):
    def test_tofflimitspicture_slot_0x73(self):
        # 0x573940 ForwardCopyRgn: RET 4 proves exactly one stack dword.
        fact = facts("imm", 4)
        zero_arg = member(0x573940, "TOffLimitsPicture", "ForwardCopyRgn", "undefined", "")
        one_arg = member(
            0x573940, "TOffLimitsPicture", "ForwardCopyRgn", "undefined", "RgnHandle srcRegion"
        )
        self.assertEqual(classify_slot(zero_arg, fact, None).verdict, "proven_conflict")
        self.assertEqual(classify_slot(one_arg, fact, None).verdict, "strong_support")

    def test_tarmymgr_slot_0x0e_two_args(self):
        # 0x4a3200 TryCreateTacticalBattleViewForTileArmies: RET 0x8 proves two
        # stack dwords; the previous 0-arg declaration was a poison pill.
        fact = facts("imm", 8)
        zero_arg = member(
            0x4A3200, "TArmyMgr", "OrphanCallChain_C2_I44_004a3200", "undefined", ""
        )
        two_arg = member(
            0x4A3200, "TArmyMgr", "TryCreateTacticalBattleViewForTileArmies", "bool",
            "TArmyStack* stack, short ownerNationCode",
        )
        self.assertEqual(classify_slot(zero_arg, fact, None).verdict, "proven_conflict")
        self.assertEqual(classify_slot(two_arg, fact, None).verdict, "strong_support")

    def test_void_but_consumed_return(self):
        fact = facts("plain", 0, ret_use={"eax": 3})
        void_decl = member(0x500000, "TFoo", "DoThing", "void", "")
        finding = classify_slot(void_decl, fact, None)
        self.assertEqual(finding.verdict, "proven_conflict")
        self.assertTrue(any("consume the return register" in r for r in finding.reasons))

    def test_slot_address_match_proves_nothing_about_signature(self):
        # The core lesson: perfect slot->address assignment with a wrong
        # signature must still be a proven conflict.
        fact = facts("imm", 0x10)
        wrong = member(0x527040, "TMapMaker", "QueryStepValue", "TEventHandler*", "")
        self.assertEqual(classify_slot(wrong, fact, None).verdict, "proven_conflict")

    def test_unknowable_args_stay_provisional(self):
        # By-value class args make the dword count unknowable: never guess.
        fact = facts("imm", 0x10)
        decl = member(0x500000, "TFoo", "TakesByValue", "void", "CString text")
        finding = classify_slot(decl, fact, None)
        self.assertNotEqual(finding.verdict, "proven_conflict")

    def test_tail_jmp_body_is_not_conflated(self):
        # ret_kind 'none' (pure tail-jmp thunk-like body) carries no RET truth.
        fact = facts("none", 0)
        decl = member(0x550F60, "TShip", "InvokeOrderNodeOwnerVfunc38", "int", "")
        self.assertNotEqual(classify_slot(decl, fact, None).verdict, "proven_conflict")


class TestOverrides(unittest.TestCase):
    def test_override_match_accepts(self):
        fact = facts("imm", 0x10)
        decl = member(
            0x527040, "TMapMaker", "AssignRegionClassToCellAndNeighbors", "int",
            "int cellIndex, int mode, int classIndex, int retryBudget",
        )
        proto = (
            "int TMapMaker::AssignRegionClassToCellAndNeighbors"
            "(int cellIndex, int mode, int classIndex, int retryBudget)"
        )
        finding = classify_slot(decl, fact, proto)
        self.assertEqual(finding.verdict, "strong_support")
        self.assertTrue(finding.overridden)

    def test_override_drift_is_conflict(self):
        fact = facts("imm", 0x10)
        drifted = member(0x527040, "TMapMaker", "AssignRegionClassToCellAndNeighbors", "int", "")
        proto = (
            "int TMapMaker::AssignRegionClassToCellAndNeighbors"
            "(int cellIndex, int mode, int classIndex, int retryBudget)"
        )
        finding = classify_slot(drifted, fact, proto)
        self.assertEqual(finding.verdict, "proven_conflict")
        self.assertTrue(any("drifted" in r for r in finding.reasons))


class TestExtentRules(unittest.TestCase):
    """The TMapMaker null-tail / adjacent stretch-table boundary."""

    def test_resume_after_null_run_stops(self):
        # slots: [getter, f, f, null, null, f(stretch<T>)] — the resumed function
        # pointer after the null run must NOT extend TMapMaker's vtable.
        decision = extent_decision(5, False, "stretch_helper", null_run_seen=True)
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason, "resume_after_null_run")

    def test_null_slots_do_not_stop(self):
        self.assertFalse(extent_decision(3, True, None, null_run_seen=False).stop)
        self.assertFalse(extent_decision(4, True, None, null_run_seen=True).stop)

    def test_contiguous_functions_continue(self):
        self.assertFalse(extent_decision(2, False, "SomeMethod", null_run_seen=False).stop)

    def test_rtti_getter_boundary_still_stops(self):
        decision = extent_decision(6, False, "GetTNextClassNamePointer", null_run_seen=False)
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason, "rtti_getter")

    def test_unresolved_data_stops(self):
        decision = extent_decision(4, False, None, null_run_seen=False)
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason, "unresolved")

    def test_known_vtable_address_is_a_precise_boundary(self):
        decision = extent_decision(
            30, False, "SomeMethod", null_run_seen=False, at_known_vtable=True
        )
        self.assertTrue(decision.stop)
        self.assertEqual(decision.reason, "known_vtable")

    def test_midtable_classname_virtual_is_not_a_boundary_with_known_set(self):
        # TView slot 26 resolves to TEventHandler's class-name getter — a REAL
        # inherited virtual, not the next table. With the known-vtable address
        # set available the name heuristic must be disabled (it truncated 245
        # view-family extractions at 26 slots).
        decision = extent_decision(
            26, False, "GetTEventHandlerClassNamePointer", null_run_seen=False,
            at_known_vtable=False, use_getter_heuristic=False,
        )
        self.assertFalse(decision.stop)


class TestDeclarationParsing(unittest.TestCase):
    def test_member_definition(self):
        parsed = parse_definition_head(
            "int TMapMaker::AssignRegionClassToCellAndNeighbors(int cellIndex, int mode, "
            "int classIndex, int retryBudget)"
        )
        self.assertEqual(
            parsed,
            (
                "int", "TMapMaker", "AssignRegionClassToCellAndNeighbors",
                "int cellIndex, int mode, int classIndex, int retryBudget", "",
            ),
        )

    def test_ctor_and_dtor(self):
        self.assertEqual(
            parse_definition_head("TShip::TShip()"), (None, "TShip", "TShip", "", "")
        )
        self.assertEqual(
            parse_definition_head("TMapMaker::~TMapMaker()"),
            (None, "TMapMaker", "~TMapMaker", "", ""),
        )

    def test_free_cdecl(self):
        self.assertEqual(
            parse_definition_head("float __cdecl Score(float* vector, int count)"),
            ("float", None, "Score", "float* vector, int count", "__cdecl"),
        )

    def test_arg_dwords(self):
        self.assertEqual(arg_stack_dwords(""), 0)
        self.assertEqual(arg_stack_dwords("void"), 0)
        self.assertEqual(arg_stack_dwords("int a, int b"), 2)
        self.assertEqual(arg_stack_dwords("TZone* zone, short n, char c"), 3)
        self.assertEqual(arg_stack_dwords("double x"), 2)
        self.assertEqual(arg_stack_dwords("RgnHandle srcRegion"), 1)
        self.assertIsNone(arg_stack_dwords("CString text"))  # by-value class: refuse
        self.assertIsNone(arg_stack_dwords("int a, ..."))  # varargs: per-callsite

    def test_ret_width(self):
        self.assertEqual(ret_width_class("void"), "void")
        self.assertEqual(ret_width_class("char"), "byte")
        self.assertEqual(ret_width_class("TView*"), "dword")
        self.assertEqual(ret_width_class("undefined"), "unknown")
        self.assertEqual(ret_width_class("float"), "fp")


if __name__ == "__main__":
    unittest.main()
