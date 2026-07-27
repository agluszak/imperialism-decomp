"""Detection tests for the Hard Rule policy gates (bd imperialism-decomp-x1cl).

These gates parse C++ with regexes over a tree that changes constantly. The failure that
matters is not a crash -- it is a pattern quietly ceasing to match, after which the gate
still exits 0 and reports clean while enforcing nothing. A green gate that enforces
nothing is worse than no gate, because the whole point is that CLAUDE.md's hard bans are
mechanically checked rather than remembered.

So every test here is a POSITIVE detection test: feed the gate a construct its own
comments say is banned and assert it is caught. The negative cases exist only to pin
exclusions that were deliberately built in, so that tightening a pattern later cannot
silently start rejecting legitimate source.

This covers the three Hard Rule enforcers the bead lists first. The remaining 15 modules
are still untested and stay on the bead.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.workflow.check_construction_antipatterns import count_patterns as construction_counts
from tools.workflow.check_marker_hygiene import (
    FUNCTION_MARKER_RE,
    is_declaration_line,
    normalize_offset,
)
from tools.workflow.check_no_raw_vtable_calls import count_patterns as vtable_counts


class _SourceCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _counts(self, counter, source: str) -> dict[str, int]:
        path = Path(self._tmp.name) / "sample.cpp"
        path.write_text(source, encoding="utf-8")
        return {key: value for key, value in counter(path).items() if value}


class ConstructionAntipatternDetectionTest(_SourceCase):
    def assert_flags(self, source: str, key: str) -> None:
        hits = self._counts(construction_counts, source)
        self.assertIn(key, hits, f"{key!r} not detected; gate reported {hits}")

    def test_inline_asm_is_flagged(self) -> None:
        self.assert_flags("void f() { __asm { nop } }\n", "inline_asm")

    def test_placement_new_on_this_is_flagged(self) -> None:
        self.assert_flags("void f() { new (this) TBase(); }\n", "placement_new_this")

    def test_manual_vptr_write_through_this_is_flagged(self) -> None:
        self.assert_flags("void f() { *(void**)this = &g_vtbl; }\n", "manual_vptr_write")

    def test_manual_vptr_write_through_member_is_flagged(self) -> None:
        self.assert_flags("void f() { obj->vftable = &g_vtbl_TFoo; }\n", "manual_vptr_write")

    def test_thiscall_cast_is_flagged(self) -> None:
        self.assert_flags(
            "auto fn = reinterpret_cast<void(__thiscall*)(void*)>(0x401000);\n", "thiscall_cast"
        )

    def test_fastcall_dummy_edx_cast_is_flagged(self) -> None:
        self.assert_flags(
            "auto fn = reinterpret_cast<int(__fastcall*)(void*, int)>(0x401000);\n",
            "fastcall_dummy_edx",
        )

    def test_bridge_names_are_flagged(self) -> None:
        for source, name in (
            ("void ConstructTBaseAtThis(TBase* self);\n", "ConstructTBaseAtThis"),
            ("void VCall_FooRuntime(void* self);\n", "VCall_FooRuntime"),
            ("void DestructTFooAndMaybeFree(TFoo* self);\n", "DestructTFooAndMaybeFree"),
        ):
            with self.subTest(name=name):
                self.assert_flags(source, "bridge_name")

    def test_operator_new_factory_is_flagged(self) -> None:
        self.assert_flags("void* TFoo::operator new(size_t n) { return 0; }\n", "operator_new_delete")

    def test_raw_this_offset_is_flagged(self) -> None:
        self.assert_flags(
            "short v = *(short*)(reinterpret_cast<char*>(this) + 0x14);\n", "raw_this_offset"
        )

    def test_offset_zero_out_param_write_is_not_a_vptr_write(self) -> None:
        # Deliberately excluded: TFileStream::ReadObject stores a deserialized object
        # pointer through a void** out-param. The RHS is not vtable-shaped.
        hits = self._counts(construction_counts, "void f(void** out) { *out = object; }\n")
        self.assertNotIn("manual_vptr_write", hits)

    def test_ordinary_source_is_clean(self) -> None:
        source = (
            "void TCity::EndCityPhase() {\n"
            "  this->ownerNationAc->SetCityPolicies();\n"
            "  delete this;\n"
            "}\n"
        )
        self.assertEqual(self._counts(construction_counts, source), {})


class RawVtableCallDetectionTest(_SourceCase):
    def assert_flags(self, source: str, key: str) -> None:
        hits = self._counts(vtable_counts, source)
        self.assertIn(key, hits, f"{key!r} not detected; gate reported {hits}")

    def test_raw_vtable_index_is_flagged(self) -> None:
        self.assert_flags("auto fn = (*reinterpret_cast<void***>(obj))[3];\n", "raw_vtable_index")

    def test_fn_typedef_cast_is_flagged(self) -> None:
        self.assert_flags("auto fn = reinterpret_cast<RestockFn>(slot);\n", "fn_typedef_cast")

    def test_vftable_index_is_flagged(self) -> None:
        self.assert_flags("auto fn = obj->vftable[0x0e];\n", "vftable_index")

    def test_vcall_facade_is_flagged(self) -> None:
        self.assert_flags("VCall_TFoo_CallSlot2C(this);\n", "vcall_facade")

    def test_real_virtual_call_is_clean(self) -> None:
        self.assertEqual(self._counts(vtable_counts, "order->Restock();\n"), {})


class MarkerHygieneDetectionTest(unittest.TestCase):
    """Hard Rules 3 and 4: the marker must be immediately followed by the declaration."""

    def test_marker_regex_matches_the_canonical_form(self) -> None:
        match = FUNCTION_MARKER_RE.search("// FUNCTION: IMPERIALISM 0x004dfd30")
        self.assertIsNotNone(match)

    def test_offsets_normalize_across_zero_padding_and_case(self) -> None:
        # reccmp pairs by address, so every spelling of one address must be one key or a
        # duplicate implementation escapes Hard Rule 4.
        canonical = normalize_offset("0x4dfd30")
        for spelling in ("0x004dfd30", "0x004DFD30", "4dfd30"):
            with self.subTest(spelling=spelling):
                self.assertEqual(normalize_offset(spelling), canonical)

    def test_declaration_line_is_recognised(self) -> None:
        for line in (
            "void TCity::EndCityPhase() {",
            "COLORREF TModuleLibraryCacheTableStateB::ResolvePaletteIndexColor(unsigned int p) {",
        ):
            with self.subTest(line=line):
                self.assertTrue(is_declaration_line(line))

    def test_comment_and_blank_lines_are_not_declarations(self) -> None:
        # These are exactly what Hard Rule 3 forbids between marker and declaration:
        # blank lines, line comments, and block comments alike.
        for line in ("", "   ", "// explanatory comment", "/* block */", "  /* indented */"):
            with self.subTest(line=repr(line)):
                self.assertFalse(is_declaration_line(line))


if __name__ == "__main__":
    unittest.main()
