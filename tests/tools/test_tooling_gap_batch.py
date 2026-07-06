#!/usr/bin/env python3
"""Tests for the 2026-07 tooling-gap batch: triage classification, empty-body
scanning, stub-count/datacmp ratchets, and typedef-vs-binary arity checks."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.reccmp.triage import classify_pair, triage_entity
from tools.workflow.check_datacmp_baseline import compare as datacmp_compare
from tools.workflow.check_datacmp_baseline import parse_report
from tools.workflow.check_empty_bodies import classify_finding, scan_file
from tools.workflow.check_stub_count import compare_counts
from tools.workflow.check_typedef_ghidra_args import arg_dwords, classify

DATA_RANGES = [(0x63E000, 0x6A0000)]
SYMBOLS = {0x4B2570: "TCity::InitializeCityProductionState"}
OWNERSHIP = {0x4B2570: "manual"}


def pair(o: str, r: str):
    return classify_pair(o, r, DATA_RANGES, SYMBOLS, OWNERSHIP)


class TriageClassifyTests(unittest.TestCase):
    def test_field_offset(self) -> None:
        bucket, detail = pair(
            "mov eax, dword ptr [esi + 0x24]", "mov eax, dword ptr [esi + 0x28]"
        )
        self.assertEqual(bucket, "field_offset")
        self.assertIn("0x24", detail)

    def test_stack_layout_on_esp(self) -> None:
        bucket, _ = pair("lea ecx, [esp + 0x34]", "lea ecx, [esp + 0x30]")
        self.assertEqual(bucket, "stack_layout")

    def test_vtable_slot_call(self) -> None:
        bucket, detail = pair(
            "call dword ptr [edx + 0xdc]", "call dword ptr [edx + 0xb8]"
        )
        self.assertEqual(bucket, "call_target")
        self.assertIn("vtable slot", detail)

    def test_direct_call_reports_ownership(self) -> None:
        bucket, detail = pair("call 0x4b2570", "call TSomethingElse")
        self.assertEqual(bucket, "call_target")
        self.assertIn("TCity::InitializeCityProductionState", detail)
        self.assertIn("manual", detail)

    def test_missing_annotation(self) -> None:
        bucket, _ = pair(
            "mov eax, <OFFSET1>", "mov eax, g_apNationStates (DATA)"
        )
        self.assertEqual(bucket, "missing_annotation")

    def test_constant_in_data_flagged_as_address(self) -> None:
        bucket, detail = pair("push 0x63f000", "push 0x10")
        self.assertEqual(bucket, "constant")
        self.assertIn("in-data", detail)

    def test_branch_displacement_is_not_constant(self) -> None:
        bucket, _ = pair("jl -0x1d", "jl -0x17")
        self.assertNotEqual(bucket, "constant")

    def test_reg_alloc(self) -> None:
        bucket, _ = pair("movsx ecx, ax", "movsx edx, ax")
        self.assertEqual(bucket, "reg_alloc")

    def test_recomp_source_tag_stripped(self) -> None:
        self.assertIsNone(pair("ret", "ret  \t(stubs_part009.cpp:228)"))

    def test_unpaired_block_is_codegen(self) -> None:
        entity = {
            "diff": [
                ["@@", [{"orig": [["0x1000", "push ebx"]], "recomp": []}]],
            ]
        }
        buckets = triage_entity(entity, DATA_RANGES, SYMBOLS, OWNERSHIP)
        self.assertEqual(list(buckets), ["codegen"])
        self.assertIn("orig-only", buckets["codegen"][0][1])


class EmptyBodyScanTests(unittest.TestCase):
    def scan(self, source: str, symbols=None):
        symbols = symbols or {}
        addr_sizes = {addr: size for addr, size in symbols.values()}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "T.cpp"
            p.write_text(source, encoding="utf-8")
            return scan_file(p, symbols, addr_sizes, max_noop_size=16)

    def test_macro_bodies_ignored(self) -> None:
        self.assertEqual(
            self.scan("#define SLOT(n) virtual void Slot##n() {}\n"), []
        )

    def test_init_list_ctor_ignored(self) -> None:
        self.assertEqual(self.scan("TFoo::TFoo() : TBase() {}\n"), [])

    def test_void_cast_body_is_empty(self) -> None:
        src = "void TCity::InitializeCityProductionState(int m) { (void)m; }\n"
        symbols = {"TCity::InitializeCityProductionState": (0x4B2570, 2210)}
        findings = self.scan(src, symbols)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "empty_but_big")

    def test_marker_small_body_verified(self) -> None:
        src = (
            "// FUNCTION: IMPERIALISM 0x00596080\n"
            "void TWorldView::NoOpHook() {}\n"
        )
        symbols = {"TWorldView::NoOpHook": (0x596080, 3)}
        self.assertEqual(self.scan(src, symbols), [])

    def test_inclass_definition_gets_class_qualifier(self) -> None:
        src = "class TBar {\n  virtual void Hook() {}\n};\n"
        symbols = {"TBar::Hook": (0x1234, 400)}
        findings = self.scan(src, symbols)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "TBar::Hook")
        self.assertEqual(findings[0]["kind"], "empty_but_big")

    def test_noop_contradicted(self) -> None:
        kind = classify_finding(
            marker_kind=None, marker_addr=None, noop_addr=0x1000,
            resolved_addr=0x1000, size=500, ctor_dtor=False, max_noop_size=16,
        )
        self.assertEqual(kind, "noop_contradicted")

    def test_empty_dtor_with_marker_is_fine_even_when_big(self) -> None:
        kind = classify_finding(
            marker_kind="SYNTHETIC", marker_addr=0x1000, noop_addr=None,
            resolved_addr=0x1000, size=200, ctor_dtor=True, max_noop_size=16,
        )
        self.assertEqual(kind, "EMPTY-VERIFIED")

    def test_unmarked_unresolved(self) -> None:
        kind = classify_finding(
            marker_kind=None, marker_addr=None, noop_addr=None,
            resolved_addr=None, size=None, ctor_dtor=False, max_noop_size=16,
        )
        self.assertEqual(kind, "empty_unresolved")


class StubCountGateTests(unittest.TestCase):
    def test_rise_fails(self) -> None:
        code, message = compare_counts(2300, 2204)
        self.assertEqual(code, 1)
        self.assertIn("prune trap", message)

    def test_drop_passes_with_ratchet_hint(self) -> None:
        code, message = compare_counts(2100, 2204)
        self.assertEqual(code, 0)
        self.assertIn("stub-count-gate-update", message)

    def test_equal_passes(self) -> None:
        self.assertEqual(compare_counts(2204, 2204)[0], 0)


class DatacmpGateTests(unittest.TestCase):
    REPORT = (
        "g_Foo (0x63e038) ... WARN \n"
        "  Unknown or unsupported data type, comparing raw data only.\n"
        "    + 0x00                                  236 : 148 \n"
        "    + 0x01                                  65 : 43 \n"
        "g_Bar (0x63e03c) ... WARN \n"
        "    + 0x00                                  1 : 2 \n"
    )

    def test_parse(self) -> None:
        entries = parse_report(self.REPORT)
        self.assertEqual(entries["g_Foo"]["diffs"], "2")
        self.assertEqual(entries["g_Bar"]["address"], "0x63e03c")

    def test_crt_descriptors_skipped(self) -> None:
        # CRuntimeClass descriptors are relocation noise: drop them and any of
        # their detail lines, without swallowing the next real variable.
        report = (
            "TArmyPlayer::classTArmyPlayer (0x669488) ... WARN \n"
            "    + 0x00                                  1 : 2 \n"
            "    + 0x0c                                  3 : 4 \n"
            "g_Real (0x63e040) ... WARN \n"
            "    + 0x00                                  5 : 6 \n"
        )
        entries = parse_report(report)
        self.assertNotIn("TArmyPlayer::classTArmyPlayer", entries)
        self.assertEqual(set(entries), {"g_Real"})
        self.assertEqual(entries["g_Real"]["diffs"], "1")

    def test_new_variable_fails(self) -> None:
        current = parse_report(self.REPORT)
        baseline = {"g_Foo": {"name": "g_Foo", "address": "0x63e038", "status": "WARN", "diffs": "2"}}
        violations, _ = datacmp_compare(current, baseline)
        self.assertEqual(len(violations), 1)
        self.assertIn("g_Bar", violations[0])

    def test_diff_growth_fails_and_shrink_improves(self) -> None:
        current = parse_report(self.REPORT)
        baseline = {
            "g_Foo": {"name": "g_Foo", "address": "0x63e038", "status": "WARN", "diffs": "1"},
            "g_Bar": {"name": "g_Bar", "address": "0x63e03c", "status": "WARN", "diffs": "5"},
        }
        violations, improved = datacmp_compare(current, baseline)
        self.assertEqual(len(violations), 1)
        self.assertIn("g_Foo", violations[0])
        self.assertEqual(improved, 1)


class TypedefArgsTests(unittest.TestCase):
    def test_arg_dwords(self) -> None:
        self.assertEqual(arg_dwords("void"), 0)
        self.assertEqual(arg_dwords(""), 0)
        self.assertEqual(arg_dwords("int a, void* b"), 2)
        self.assertEqual(arg_dwords("double d, int i"), 3)
        self.assertIsNone(arg_dwords("int a, ..."))

    def test_cdecl_on_callee_cleaned_is_strong(self) -> None:
        verdict = classify("__cdecl", 3, ret_imm=12, ghidra_params=3)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict[0], "STRONG")
        self.assertIn("CONVENTION", verdict[1])

    def test_stdcall_arity_mismatch_is_strong(self) -> None:
        verdict = classify("__stdcall", 2, ret_imm=12, ghidra_params=3)
        self.assertEqual(verdict[0], "STRONG")

    def test_matching_cdecl_is_clean(self) -> None:
        self.assertIsNone(classify("__cdecl", 2, ret_imm=0, ghidra_params=2))

    def test_ghidra_delta_is_weak(self) -> None:
        verdict = classify("(default)", 2, ret_imm=0, ghidra_params=0)
        self.assertEqual(verdict[0], "WEAK")


if __name__ == "__main__":
    unittest.main()
