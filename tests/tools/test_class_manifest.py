#!/usr/bin/env python3
"""Tests for tools.common.class_manifest."""

from __future__ import annotations

import unittest

from tools.common.class_manifest import (
    _as_int,
    _is_safe_plain,
    _normalize_mapping,
    _normalize_scalar,
    hex2,
    hex8,
    dump_manifest,
    loads_manifest,
    merge_refresh,
    curated_slot_methods,
    slot_method_overrides,
    recovered_field_rows,
    vtable_aliases,
    vtable_annotation_rows,
    curated_layout,
)


class Hex8Tests(unittest.TestCase):
    def test_integer_input(self) -> None:
        self.assertEqual(hex8(0x004B44D0), "0x004b44d0")

    def test_string_input(self) -> None:
        self.assertEqual(hex8("0x004B44D0"), "0x004b44d0")

    def test_zero(self) -> None:
        self.assertEqual(hex8(0), "0x00000000")

    def test_small_value(self) -> None:
        self.assertEqual(hex8(0xFF), "0x000000ff")


class Hex2Tests(unittest.TestCase):
    def test_small_value(self) -> None:
        self.assertEqual(hex2(4), "0x04")

    def test_larger_value(self) -> None:
        self.assertEqual(hex2(0x278), "0x278")

    def test_string_input(self) -> None:
        self.assertEqual(hex2("0x1D"), "0x1d")

    def test_zero(self) -> None:
        self.assertEqual(hex2(0), "0x00")


class AsIntTests(unittest.TestCase):
    def test_int_passthrough(self) -> None:
        self.assertEqual(_as_int(42), 42)

    def test_hex_string(self) -> None:
        self.assertEqual(_as_int("0x1A"), 0x1A)

    def test_plain_hex_string(self) -> None:
        self.assertEqual(_as_int("FF"), 0xFF)

    def test_bool_raises(self) -> None:
        with self.assertRaises(TypeError):
            _as_int(True)


class IsSafePlainTests(unittest.TestCase):
    def test_identifier(self) -> None:
        self.assertTrue(_is_safe_plain("TFoo"))

    def test_with_colons(self) -> None:
        self.assertTrue(_is_safe_plain("TFoo::Bar"))

    def test_with_underscore(self) -> None:
        self.assertTrue(_is_safe_plain("_field"))

    def test_digit_leading(self) -> None:
        self.assertFalse(_is_safe_plain("0xABC"))

    def test_yaml_keyword(self) -> None:
        self.assertFalse(_is_safe_plain("true"))
        self.assertFalse(_is_safe_plain("false"))
        self.assertFalse(_is_safe_plain("null"))
        self.assertFalse(_is_safe_plain("yes"))
        self.assertFalse(_is_safe_plain("no"))

    def test_empty_string(self) -> None:
        self.assertFalse(_is_safe_plain(""))

    def test_with_spaces(self) -> None:
        self.assertFalse(_is_safe_plain("foo bar"))

    def test_with_punctuation(self) -> None:
        self.assertFalse(_is_safe_plain("foo(bar)"))


class NormalizeScalarTests(unittest.TestCase):
    def test_addr_field_hex8(self) -> None:
        self.assertEqual(_normalize_scalar("vtable_addr", 0x004B44D0), "0x004b44d0")
        self.assertEqual(_normalize_scalar("target", "0x004B44D0"), "0x004b44d0")

    def test_small_field_hex2(self) -> None:
        self.assertEqual(_normalize_scalar("index", 4), "0x04")
        self.assertEqual(_normalize_scalar("object_size", 0x278), "0x278")

    def test_other_field_passthrough(self) -> None:
        self.assertEqual(_normalize_scalar("kind", "override"), "override")
        self.assertEqual(_normalize_scalar("ghidra_name", "Foo"), "Foo")

    def test_none_passthrough(self) -> None:
        self.assertIsNone(_normalize_scalar("vtable_addr", None))


class NormalizeMappingTests(unittest.TestCase):
    def test_nested_normalization(self) -> None:
        data = {"vtable_addr": 0x004B44D0, "index": 4}
        result = _normalize_mapping(data)
        self.assertEqual(result["vtable_addr"], "0x004b44d0")
        self.assertEqual(result["index"], "0x04")

    def test_list_of_dicts(self) -> None:
        data = {"slots": [{"index": 0, "target": 0x00485E20}]}
        result = _normalize_mapping(data)
        self.assertEqual(result["slots"][0]["index"], "0x00")
        self.assertEqual(result["slots"][0]["target"], "0x00485e20")


class DumpManifestRoundtripTests(unittest.TestCase):
    def test_minimal_manifest(self) -> None:
        manifest = {
            "class": "TFoo",
            "generated": {
                "vtable_addr": "0x004b44d0",
                "object_size": "0x10",
                "slots": [],
            },
            "curated": {},
        }
        text = dump_manifest(manifest)
        self.assertIn("class: TFoo", text)
        self.assertIn("vtable_addr: 0x004b44d0", text)

    def test_roundtrip_preserves_structure(self) -> None:
        manifest = {
            "class": "TBar",
            "generated": {
                "vtable_addr": "0x004b44d0",
                "object_size": "0x20",
                "base": "TObject",
                "ancestry": ["TObject", "CObject"],
                "root": "CObject",
                "slots": [
                    {
                        "index": "0x00",
                        "byte": "0x00",
                        "target": "0x00485e20",
                        "kind": "inherited",
                        "is_thunk": False,
                        "is_null": False,
                        "ghidra_name": "GetRuntimeClass",
                        "size": 6,
                    },
                ],
            },
            "curated": {
                "layout": {"base_offset": "0x00", "status": "recovered"},
                "slots": [{"index": "0x00", "method": "GetRuntimeClass"}],
            },
        }
        text = dump_manifest(manifest)
        reloaded = loads_manifest(text)
        self.assertEqual(reloaded["class"], "TBar")
        self.assertEqual(reloaded["generated"]["vtable_addr"], "0x004b44d0")
        self.assertEqual(len(reloaded["generated"]["slots"]), 1)
        self.assertEqual(reloaded["generated"]["slots"][0]["target"], "0x00485e20")


class MergeRefreshTests(unittest.TestCase):
    def test_preserves_curated(self) -> None:
        existing = {
            "class": "TFoo",
            "generated": {"vtable_addr": "0x00400000", "slots": []},
            "curated": {"slots": [{"index": "0x00", "method": "MyMethod"}]},
        }
        fresh_gen = {"vtable_addr": "0x00400000", "slots": [{"index": "0x00", "target": "0x00500000"}]}
        result = merge_refresh(existing, fresh_gen, "TFoo")
        self.assertEqual(result["generated"], fresh_gen)
        self.assertEqual(result["curated"]["slots"][0]["method"], "MyMethod")

    def test_none_existing_uses_empty_curated(self) -> None:
        result = merge_refresh(None, {"vtable_addr": "0x00400000"}, "TFoo")
        self.assertEqual(result["curated"], {})


class CuratedSlotMethodsTests(unittest.TestCase):
    def test_extracts_curated_slots(self) -> None:
        manifest = {
            "curated": {
                "slots": [
                    {"index": "0x00", "method": "GetRuntimeClass", "confidence": "high"},
                    {"index": "0x02", "method": "Serialize"},
                ]
            }
        }
        result = curated_slot_methods(manifest)
        self.assertIn(0, result)
        self.assertIn(2, result)
        self.assertEqual(result[0]["method"], "GetRuntimeClass")

    def test_empty_curated(self) -> None:
        result = curated_slot_methods({})
        self.assertEqual(result, {})


class SlotMethodOverridesTests(unittest.TestCase):
    def test_extracts_overrides_from_manifests(self) -> None:
        manifests = {
            "TFoo": {
                "curated": {
                    "slots": [{"index": "0x00", "method": "GetRuntimeClass"}]
                }
            }
        }
        result = slot_method_overrides(manifests)
        self.assertIn(("TFoo", 0), result)
        self.assertEqual(result[("TFoo", 0)]["method_name"], "GetRuntimeClass")

    def test_skips_slots_without_method(self) -> None:
        manifests = {
            "TFoo": {
                "curated": {
                    "slots": [{"index": "0x00"}]
                }
            }
        }
        result = slot_method_overrides(manifests)
        self.assertEqual(result, {})


class RecoveredFieldRowsTests(unittest.TestCase):
    def test_extracts_field_rows(self) -> None:
        manifests = {
            "TFoo": {
                "curated": {
                    "fields": [
                        {"offset": "0x04", "type": "int", "name": "m_count", "evidence": "asm"},
                    ]
                }
            }
        }
        rows = recovered_field_rows(manifests)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["class"], "TFoo")
        self.assertEqual(rows[0]["offset"], "0x04")
        self.assertEqual(rows[0]["field_type"], "int")
        self.assertEqual(rows[0]["field_name"], "m_count")


class VtableAliasesTests(unittest.TestCase):
    def test_extracts_aliases(self) -> None:
        manifests = {
            "TFoo": {
                "curated": {
                    "aliases": [{"alias_class": "TBar"}]
                }
            }
        }
        result = vtable_aliases(manifests)
        self.assertEqual(result, {"TBar": "TFoo"})

    def test_empty_aliases(self) -> None:
        manifests = {"TFoo": {"curated": {}}}
        result = vtable_aliases(manifests)
        self.assertEqual(result, {})


class VtableAnnotationRowsTests(unittest.TestCase):
    def test_extracts_annotations(self) -> None:
        manifests = {
            "TFoo": {
                "curated": {
                    "vtable_annotation": {"address": "4b44d0", "note": "duplicate disambig"}
                }
            }
        }
        rows = vtable_annotation_rows(manifests)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["class"], "TFoo")
        self.assertEqual(rows[0]["address"], "4b44d0")


class CuratedLayoutTests(unittest.TestCase):
    def test_returns_layout(self) -> None:
        manifest = {"curated": {"layout": {"status": "recovered"}}}
        self.assertEqual(curated_layout(manifest), {"status": "recovered"})

    def test_returns_empty_when_missing(self) -> None:
        self.assertEqual(curated_layout({}), {})
        self.assertEqual(curated_layout({"curated": {}}), {})


if __name__ == "__main__":
    unittest.main()
