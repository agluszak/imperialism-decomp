"""Tests for the no_rtti class audit's pure classification core and the
source-side ctor/dtor address discovery.

The Ghidra-dependent evidence collectors (decompiling live functions) aren't
unit-testable without a running project — those are covered by running the
real tool against the vendored DB (build evidence), not here.
"""

import tempfile
import unittest
from pathlib import Path

from tools.ghidra.no_rtti_class_audit import (
    classify_no_rtti_record,
    find_known_addrs,
    find_operator_new_feeding_ctor,
    find_zero_field_derived,
)


class ClassifyNoRttiRecordTests(unittest.TestCase):
    def test_no_evidence(self):
        verdict, notes = classify_no_rtti_record(0x14, [])
        self.assertEqual(verdict, "no_binary_size_evidence")
        self.assertIn("no original-binary evidence", notes)

    def test_allocation_exact_match(self):
        """operator_new(0xNN) matching the source size -> verified."""
        verdict, notes = classify_no_rtti_record(0x14, [
            {"kind": "operator_new_exact", "value": 0x14, "address": "0x401000", "note": "ctor caller"},
        ])
        self.assertEqual(verdict, "binary_size_verified")
        self.assertIn("operator_new_exact=0x14", notes)

    def test_allocation_exact_mismatch_is_contradiction(self):
        verdict, notes = classify_no_rtti_record(0x10, [
            {"kind": "operator_new_exact", "value": 0x14, "address": "0x401000", "note": ""},
        ])
        self.assertEqual(verdict, "source_binary_contradiction")
        self.assertIn("0x14", notes)
        self.assertIn("0x10", notes)

    def test_conflicting_exact_evidence_is_contradiction(self):
        """Two independent exact sources disagreeing with each other, even if
        one happens to match source_size, is a contradiction worth flagging."""
        verdict, notes = classify_no_rtti_record(0x14, [
            {"kind": "operator_new_exact", "value": 0x14, "address": "0x401000", "note": ""},
            {"kind": "external_sdk_header", "value": 0x18, "address": "", "note": "sdk"},
        ])
        self.assertEqual(verdict, "source_binary_contradiction")

    def test_stack_object_derived_zero_field_exact(self):
        """A zero-own-field derived class's exact size transfers to the base."""
        verdict, notes = classify_no_rtti_record(0x74, [
            {"kind": "derived_zero_own_fields_exact", "value": 0x74, "address": "",
             "note": "TLowDiskWarningDialog derives at offset 0"},
        ])
        self.assertEqual(verdict, "binary_size_verified")

    def test_lower_bound_consistent(self):
        """ctor/dtor touches an offset within the source size -> lower bound only."""
        verdict, notes = classify_no_rtti_record(0x20, [
            {"kind": "ctor_dtor_max_offset", "value": 0x10, "address": "0x401000", "note": "ctor"},
        ])
        self.assertEqual(verdict, "binary_lower_bound_only")

    def test_lower_bound_exceeds_source_is_contradiction(self):
        """ctor/dtor touches an offset BEYOND the declared source size -> the
        source is missing trailing bytes; a genuine contradiction to block on."""
        verdict, notes = classify_no_rtti_record(0x10, [
            {"kind": "ctor_dtor_max_offset", "value": 0x18, "address": "0x401000", "note": "dtor"},
        ])
        self.assertEqual(verdict, "source_binary_contradiction")
        self.assertIn("0x18", notes)

    def test_upper_bound_consistent(self):
        verdict, notes = classify_no_rtti_record(0x10, [
            {"kind": "upper_bound_from_sibling", "value": 0x20, "address": "", "note": ""},
        ])
        self.assertEqual(verdict, "binary_upper_bound_only")

    def test_upper_bound_below_source_is_contradiction(self):
        verdict, notes = classify_no_rtti_record(0x20, [
            {"kind": "upper_bound_from_sibling", "value": 0x10, "address": "", "note": ""},
        ])
        self.assertEqual(verdict, "source_binary_contradiction")

    def test_exact_beats_lower_bound(self):
        """When both an exact match and a (consistent) lower bound are present,
        the verdict is the strongest (verified), and both appear in notes."""
        verdict, notes = classify_no_rtti_record(0x14, [
            {"kind": "ctor_dtor_max_offset", "value": 0x8, "address": "0x401000", "note": "ctor"},
            {"kind": "operator_new_exact", "value": 0x14, "address": "0x401010", "note": "caller"},
        ])
        self.assertEqual(verdict, "binary_size_verified")
        self.assertIn("ctor_dtor_max_offset", notes)
        self.assertIn("operator_new_exact", notes)


class FindOperatorNewFeedingCtorTests(unittest.TestCase):
    def test_direct_pairing(self):
        text = (
            "pTVar1 = (Foo *)operator_new(0x14);\n"
            "Foo::Foo(pTVar1);\n"
        )
        self.assertEqual(find_operator_new_feeding_ctor(text, "Foo::Foo"), 0x14)

    def test_regression_unrelated_allocation_in_same_function_not_matched(self):
        """The exact bug found auditing CSubViewIterator/TA1TemplateDialog: a
        caller function allocates a DIFFERENT class (here Bar, size 0x9c) and
        never actually calls Foo::Foo by name in the decompiled text at all
        (Ghidra left the real call unresolved) -- must not report Bar's size as
        Foo's evidence just because operator_new appears somewhere in the text."""
        text = (
            "pTVar1 = (Bar *)operator_new(0x9c);\n"
            "func_0x004919a0(pTVar1);\n"  # the real Foo::Foo call, unresolved by name
        )
        self.assertIsNone(find_operator_new_feeding_ctor(text, "Foo::Foo"))

    def test_tracks_the_right_variable_through_interleaved_allocations(self):
        """Several objects allocated before any of their constructors run (a
        common factory-function shape) -- matching must follow the SPECIFIC
        variable passed to Foo::Foo, not just "the nearest preceding
        operator_new text-wise" (which here would be Baz's unrelated 0x20)."""
        text = (
            "pTVar1 = (Bar *)operator_new(0x9c);\n"
            "Bar::Bar(pTVar1);\n"
            "pTVar2 = (Foo *)operator_new(0x14);\n"
            "func_unrelated();\n"
            "pTVar3 = (Baz *)operator_new(0x20);\n"
            "Foo::Foo(pTVar2);\n"
        )
        self.assertEqual(find_operator_new_feeding_ctor(text, "Foo::Foo"), 0x14)

    def test_ctor_call_on_variable_never_assigned_from_operator_new_rejected(self):
        """The ctor's `this` argument was never itself assigned from an
        operator_new call in this text (e.g. it's a stack local, or a pointer
        threaded in from elsewhere) -- must not misattribute an unrelated
        allocation just because one exists earlier in the function."""
        text = (
            "pTVar1 = (Bar *)operator_new(0x9c);\n"
            "Bar::Bar(pTVar1);\n"
            "Foo::Foo(someOtherPointer);\n"
        )
        self.assertIsNone(find_operator_new_feeding_ctor(text, "Foo::Foo"))

    def test_no_operator_new_at_all(self):
        text = "Foo::Foo(somePreallocatedPointer);\n"
        self.assertIsNone(find_operator_new_feeding_ctor(text, "Foo::Foo"))

    def test_gap_too_large_rejected(self):
        text = (
            "pTVar1 = (Foo *)operator_new(0x14);\n"
            + ("x = x + 1;\n" * 60)  # pad well past _MAX_NEW_TO_CTOR_GAP_CHARS
            + "Foo::Foo(pTVar1);\n"
        )
        self.assertIsNone(find_operator_new_feeding_ctor(text, "Foo::Foo"))


class FindKnownAddrsTests(unittest.TestCase):
    def _write(self, root: Path, rel: str, content: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_finds_anchored_ctor_and_dtor_decls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "config/original_entities.csv", "")
            self._write(root, "config/symbols.ghidra.txt", "")
            self._write(root, "include/game/Foo.h", (
                "class Foo {\n"
                "public:\n"
                "  Foo(int x); // 0x00401000\n"
                "  ~Foo();     // 0x00401050\n"
                "};\n"
            ))
            addrs = find_known_addrs(root, "Foo")
            found = {a for a, _, _ in addrs}
            self.assertIn("0x00401000", found)
            self.assertIn("0x00401050", found)

    def test_ignores_unanchored_substring_matches(self):
        """A function parameter of type `OrderSheet*` (e.g.
        `bool CanFillOrderSheet(OrderSheet* orderSheet); // 0x00401234`) must
        NOT be picked up as OrderSheet's own constructor."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "config/original_entities.csv", "")
            self._write(root, "config/symbols.ghidra.txt", "")
            self._write(root, "include/game/TCapacityOrder.h", (
                "class TCapacityOrder {\n"
                "public:\n"
                "  bool CanFillOrderSheet(OrderSheet* orderSheet); // 0x00401234\n"
                "};\n"
            ))
            addrs = find_known_addrs(root, "OrderSheet")
            self.assertEqual(addrs, [])

    def test_finds_original_entities_ctor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(
                root, "config/original_entities.csv",
                "address|name|symbol|size|type|prototype|provenance\n"
                "497320|CTemporaryRegion::CTemporaryRegion||4|function|x|\n"
                "497390|CTemporaryRegion::~CTemporaryRegion||4|function|x|\n",
            )
            self._write(root, "config/symbols.ghidra.txt", "")
            addrs = find_known_addrs(root, "CTemporaryRegion")
            found = {a for a, _, _ in addrs}
            self.assertIn("0x497320", found)
            self.assertIn("0x497390", found)

    def test_finds_definition_with_function_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "config/original_entities.csv", "")
            self._write(root, "config/symbols.ghidra.txt", "")
            self._write(root, "src/game/Bar.cpp", (
                "// FUNCTION: IMPERIALISM 0x00501000\n"
                "Bar::Bar() {}\n"
            ))
            addrs = find_known_addrs(root, "Bar")
            found = {a for a, _, _ in addrs}
            self.assertIn("0x00501000", found)

    def test_no_evidence_when_class_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "config/original_entities.csv", "")
            self._write(root, "config/symbols.ghidra.txt", "")
            addrs = find_known_addrs(root, "NeverMentioned")
            self.assertEqual(addrs, [])


class FindZeroFieldDerivedTests(unittest.TestCase):
    def test_finds_zero_own_field_derived_at_offset_zero(self):
        layouts = {
            "TModalTemplateDialog": {"bases": {"TModalDialogBase": 0}, "fields": {}, "size": 116},
            "TLowDiskWarningDialog": {
                "bases": {"TModalTemplateDialog": 0},
                "fields": {"promptText": {"offset": 116, "size": 4}},
                "size": 120,
            },
        }
        derived = find_zero_field_derived(layouts, "TModalTemplateDialog")
        self.assertEqual(derived, [])  # TModalTemplateDialog itself has no zero-field derivee here

        derived2 = find_zero_field_derived(layouts, "TModalDialogBase")
        # TModalTemplateDialog derives from TModalDialogBase at offset 0 and adds no fields.
        self.assertIn("TModalTemplateDialog", derived2)

    def test_excludes_derived_with_own_fields(self):
        layouts = {
            "Base": {"bases": {}, "fields": {}, "size": 8},
            "Derived": {"bases": {"Base": 0}, "fields": {"extra": {"offset": 8, "size": 4}}, "size": 12},
        }
        self.assertEqual(find_zero_field_derived(layouts, "Base"), [])

    def test_excludes_derived_at_nonzero_offset(self):
        layouts = {
            "Base": {"bases": {}, "fields": {}, "size": 8},
            "Derived": {"bases": {"Base": 4}, "fields": {}, "size": 12},
        }
        self.assertEqual(find_zero_field_derived(layouts, "Base"), [])


if __name__ == "__main__":
    unittest.main()
