#!/usr/bin/env python3
"""Contracts for the serialization byte-desync audit.

The audit's whole value is that it models stream *byte accounting* rather than reccmp's
match percentage, so these cover the two extraction halves and the wildcard rules that
keep it from crying wolf.
"""

from __future__ import annotations

import unittest

from pathlib import Path
import tempfile
import unittest.mock

from tools.workflow.serde_audit import (
    binary_stream_ops,
    compare,
    serial_identity_findings,
    source_stream_ops,
    _loop_blocks,
)


class SourceExtractionTest(unittest.TestCase):
    def test_literal_sizes_and_direction(self):
        ops = source_stream_ops(
            """{
              stream->ReadBytes(&field6, 2);
              stream->ReadBytes(&cityScoreTotal, 4);
              stream->WriteBytes(&field6, 2);
            }"""
        )
        self.assertEqual(
            [(op["dir"], op["bytes"], op["count"]) for op in ops],
            [("read", 2, 1), ("read", 4, 1), ("write", 2, 1)],
        )

    def test_typed_accessor_widths_come_from_the_slot_table(self):
        ops = source_stream_ops("{ short v = stream->ReadInteger(); stream->WriteInteger(3); }")
        self.assertEqual([(op["dir"], op["bytes"]) for op in ops], [("read", 2), ("write", 2)])

    def test_sizeof_width_is_a_wildcard_not_a_guess(self):
        ops = source_stream_ops("{ stream->ReadBytes(matrix, sizeof(matrix)); }")
        self.assertIsNone(ops[0]["bytes"])

    def test_literal_bounded_loop_multiplies_the_repeat_count(self):
        ops = source_stream_ops(
            """{
              for (int i = 0; i < 0x10; ++i) {
                stream->ReadBytes(&slot[i], 2);
              }
            }"""
        )
        self.assertEqual(ops[0]["count"], 0x10)

    def test_countdown_loop_form_is_recognised(self):
        ops = source_stream_ops(
            """{
              for (int remaining = 0x20; remaining != 0; --remaining) {
                stream->WriteBytes(&value, 2);
              }
            }"""
        )
        self.assertEqual(ops[0]["count"], 0x20)

    def test_non_literal_loop_bound_yields_an_unknown_count(self):
        ops = source_stream_ops(
            """{
              for (int i = 0; i < nationCount; ++i) {
                stream->ReadBytes(&entry[i], 4);
              }
            }"""
        )
        self.assertIsNone(ops[0]["count"])

    def test_byte_swap_helpers_consume_no_stream_bytes(self):
        ops = source_stream_ops(
            "{ stream->ReadBytes(m, 4); SwapShortArrayBytes(m, 2); ByteSwapShortInPlace(p); }"
        )
        self.assertEqual(len(ops), 1)

    def test_array_helpers_expand_to_element_width_times_count(self):
        ops = source_stream_ops("{ WriteShortArrayElems(stream, values, 0x211); }")
        self.assertEqual((ops[0]["dir"], ops[0]["bytes"], ops[0]["count"]), ("write", 2, 0x211))

    def test_nested_loops_multiply(self):
        blocks = _loop_blocks(
            "for (int i = 0; i < 4; ++i) { for (int j = 0; j < 3; ++j) { X; } }"
        )
        self.assertEqual(sorted(count for _, _, count in blocks), [3, 4])


class BinaryExtractionTest(unittest.TestCase):
    """The listing side is exercised against a synthetic listing, so it needs no Ghidra."""

    def setUp(self):
        import tools.workflow.serde_audit as audit

        self.audit = audit
        self.original = audit.listing_lines

    def tearDown(self):
        self.audit.listing_lines = self.original

    def patch_listing(self, lines):
        self.audit.listing_lines = lambda address, refresh=False: lines

    # A serializer's prologue: the stream arrives as the single stack argument
    # (entry-relative +4), its vtable is dereferenced, and the slot is hoisted out.
    PROLOGUE = [
        "00001000  MOV EDI,dword ptr [ESP + 0x4]",
        "00001004  MOV EAX,dword ptr [EDI]",
    ]

    def test_slot_pointer_hoisted_into_a_register(self):
        self.patch_listing(
            self.PROLOGUE
            + [
                "00001006  MOV EBX,dword ptr [EAX + 0x3c]",
                "00001005  PUSH 0x422",
                "00001007  PUSH ESI",
                "00001008  CALL EBX",
            ]
        )
        ops, _ = binary_stream_ops(0x1000)
        self.assertEqual([(op["dir"], op["bytes"]) for op in ops], [("read", 0x422)])

    def test_slot_pointer_spilled_to_a_stack_slot(self):
        # The spill displacement is meaningless without ESP tracking: the same [ESP+0x18]
        # names different slots before and after the argument pushes.
        self.patch_listing(
            [
                "00001000  SUB ESP,0x8",
                "00001001  MOV EDI,dword ptr [ESP + 0xc]",
                "00001002  MOV EBX,dword ptr [EDI]",
                "00001003  MOV EBP,dword ptr [EBX + 0x3c]",
                "00001006  PUSH 0x2",
                "00001008  PUSH EAX",
                "00001009  MOV dword ptr [ESP + 0x8],EBP",
                "0000100d  CALL EBP",
                "0000100f  PUSH 0xa4",
                "00001014  PUSH EBX",
                "00001015  CALL dword ptr [ESP + 0x8]",
            ]
        )
        ops, _ = binary_stream_ops(0x1000)
        self.assertEqual([op["bytes"] for op in ops], [2, 0xA4])

    def test_typed_accessor_slot_called_directly(self):
        self.patch_listing(
            [
                "00001000  MOV EDI,dword ptr [ESP + 0x4]",
                "00001004  MOV EBX,dword ptr [EDI]",
                "00001006  CALL dword ptr [EBX + 0x44]",
            ]
        )
        ops, _ = binary_stream_ops(0x1000)
        self.assertEqual([(op["dir"], op["bytes"]) for op in ops], [("read", 1)])

    def test_counted_loop_multiplies_its_body(self):
        self.patch_listing(
            self.PROLOGUE
            + [
                "00001006  MOV EBX,dword ptr [EAX + 0x3c]",
                "00001005  MOV ESI,0x211",
                "0000100a  PUSH 0x2",
                "0000100c  PUSH EDI",
                "0000100d  CALL EBX",
                "0000100f  DEC ESI",
                "00001010  JNZ 0x0000100a",
            ]
        )
        ops, _ = binary_stream_ops(0x1000)
        self.assertEqual(ops[0]["count"], 0x211)

    def test_vtable_pointer_spilled_and_reloaded_still_resolves(self):
        # TTown::ReadFrom parks the stream's vtable at entry and reloads it for its tail
        # call; without tracking vtable spills that trailing read looks like a missing op.
        self.patch_listing(
            [
                "00001000  MOV EDI,dword ptr [ESP + 0x4]",
                "00001004  MOV EAX,dword ptr [EDI]",
                "00001006  SUB ESP,0x4",
                "00001009  MOV dword ptr [ESP + 0x0],EAX",
                "0000100d  MOV ECX,dword ptr [ESP + 0x0]",
                "00001011  CALL dword ptr [ECX + 0x44]",
            ]
        )
        ops, _ = binary_stream_ops(0x1000)
        self.assertEqual([(op["dir"], op["bytes"]) for op in ops], [("read", 1)])

    def test_dispatch_on_another_objects_vtable_is_not_a_stream_call(self):
        # this->vtable[0x84] collides with TStream's WriteCharacter; only a slot loaded
        # from the *stream's* vtable may count. Regression: TNavyMission::ReadFrom.
        self.patch_listing(
            self.PROLOGUE
            + [
                "00001006  MOV ECX,dword ptr [ESI]",
                "00001008  MOV EBP,dword ptr [ECX + 0x84]",
                "0000100c  CALL EBP",
            ]
        )
        ops, _ = binary_stream_ops(0x1000)
        self.assertEqual(ops, [])

    def test_non_literal_size_operand_is_reported_not_invented(self):
        self.patch_listing(
            self.PROLOGUE
            + [
                "00001006  MOV EBX,dword ptr [EAX + 0x3c]",
                "00001005  PUSH ECX",
                "00001006  PUSH EDI",
                "00001007  CALL EBX",
            ]
        )
        ops, warnings = binary_stream_ops(0x1000)
        self.assertIsNone(ops[0]["bytes"])
        self.assertTrue(warnings)


class ComparisonTest(unittest.TestCase):
    def op(self, direction, size, count=1):
        return {"op": "x", "dir": direction, "bytes": size, "count": count}

    def test_identical_sequences_align(self):
        ops = [self.op("read", 2), self.op("read", 4)]
        self.assertEqual(compare(ops, list(ops))["status"], "aligned")

    def test_a_missing_trailing_group_is_a_divergence(self):
        original = [self.op("read", 2), self.op("read", 4)]
        ported = [self.op("read", 2)]
        result = compare(original, ported)
        self.assertEqual(result["status"], "divergent")
        self.assertEqual(result["index"], 1)

    def test_a_wrong_width_is_a_divergence_at_that_position(self):
        original = [self.op("read", 2), self.op("read", 2)]
        ported = [self.op("read", 2), self.op("read", 1)]
        self.assertEqual(compare(original, ported)["index"], 1)

    def test_direction_flip_is_a_divergence(self):
        self.assertEqual(
            compare([self.op("read", 2)], [self.op("write", 2)])["status"], "divergent"
        )

    def test_unknown_width_is_a_wildcard_and_is_counted(self):
        original = [self.op("read", 0x422)]
        ported = [self.op("read", None)]
        result = compare(original, ported)
        self.assertEqual(result["status"], "aligned")
        self.assertEqual(result["unverified"], 1)

    def test_unknown_repeat_count_is_also_a_wildcard(self):
        original = [self.op("read", 2, 30)]
        ported = [self.op("read", 2, None)]
        self.assertEqual(compare(original, ported)["status"], "aligned")

    def test_known_but_different_repeat_counts_diverge(self):
        original = [self.op("write", 2, 30)]
        ported = [self.op("write", 2, 1)]
        self.assertEqual(compare(original, ported)["status"], "divergent")


class SerialIdentityTest(unittest.TestCase):
    """The CObject sub-format's identity surface -- invisible to byte accounting.

    CArchive persists a class name and schema; a mismatch makes a retail save unreadable
    however correct the field code is.
    """

    def run_with(self, oracle_rows, sources):
        import tools.workflow.serde_audit as audit

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle = root / "rtti.csv"
            oracle.write_text(
                "descriptor,name,object_size,schema,createobject_thunk,createobject,"
                "base_descriptor,base_name\n" + "".join(oracle_rows),
                encoding="utf-8",
            )
            source_dir = root / "src"
            source_dir.mkdir()
            (source_dir / "x.cpp").write_text(sources, encoding="utf-8")
            with unittest.mock.patch.object(audit, "RTTI_ORACLE", oracle), unittest.mock.patch.object(
                audit, "REPO_ROOT", root
            ):
                return serial_identity_findings()

    def test_matching_identities_report_nothing(self):
        findings = self.run_with(
            ["0x1,TMission,0x10,0x1,0x2,0x3,0x4,TObject\n"],
            "IMPLEMENT_SERIAL(TMission, TObject, 1)\n",
        )
        self.assertEqual(findings, [])

    def test_schema_mismatch_is_reported(self):
        findings = self.run_with(
            ["0x1,TMission,0x10,0x2,0x2,0x3,0x4,TObject\n"],
            "IMPLEMENT_SERIAL(TMission, TObject, 1)\n",
        )
        self.assertTrue(any("schema" in f for f in findings))

    def test_base_mismatch_is_reported(self):
        findings = self.run_with(
            ["0x1,TBeachheadMission,0x10,0x1,0x2,0x3,0x4,TControlSeaZoneMission\n"],
            "IMPLEMENT_SERIAL(TBeachheadMission, TNavyMission, 1)\n",
        )
        self.assertTrue(any("chains to" in f for f in findings))

    def test_a_serial_class_we_never_declare_is_reported(self):
        findings = self.run_with(
            ["0x1,TMission,0x10,0x1,0x2,0x3,0x4,TObject\n"],
            "IMPLEMENT_DYNCREATE(TMission, TObject)\n",
        )
        self.assertTrue(any("never declares IMPLEMENT_SERIAL" in f for f in findings))

    def test_declaring_serial_on_a_dyncreate_class_is_reported(self):
        findings = self.run_with(
            ["0x1,TMission,0x10,0xffff,0x2,0x3,0x4,TObject\n"],
            "IMPLEMENT_SERIAL(TMission, TObject, 1)\n",
        )
        self.assertTrue(any("not serial" in f for f in findings))


if __name__ == "__main__":
    unittest.main()
