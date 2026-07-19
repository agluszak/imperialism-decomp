"""Tests for the semantic field-coverage report's classification logic."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.class_field_coverage import (
    build_report,
    classify_field,
    compute_inherited_bytes,
    is_pad_name,
    is_weak_name,
)


class WeakNameTests(unittest.TestCase):
    def test_weak_field_names(self):
        for name in ["field10", "field_0x94", "field", "FIELD1A"]:
            self.assertTrue(is_weak_name(name), name)

    def test_weak_pad_names(self):
        for name in ["pad", "pad04", "padding", "padding1c", "PAD_0x9c"]:
            self.assertTrue(is_weak_name(name), name)
            self.assertTrue(is_pad_name(name), name)

    def test_real_names_not_weak(self):
        for name in ["quantityField04", "ownerContextAt04", "selectedShipOrder", "vftable"]:
            self.assertFalse(is_weak_name(name), name)


class ClassifyFieldTests(unittest.TestCase):
    def test_padding_name_wins_regardless_of_type(self):
        bucket, weak = classify_field("pad04", "unsigned char")
        self.assertEqual(bucket, "padding_bytes")
        self.assertTrue(weak)

    def test_undefined_type(self):
        bucket, weak = classify_field("someField", "undefined4")
        self.assertEqual(bucket, "undefined_bytes")
        self.assertTrue(weak)

    def test_void_pointer_always_weak(self):
        bucket, weak = classify_field("ownerContext", "void *")
        self.assertEqual(bucket, "opaque_pointer_bytes")
        self.assertTrue(weak)

    def test_weak_named_primitive(self):
        bucket, weak = classify_field("field10", "int")
        self.assertEqual(bucket, "primitive_unknown_bytes")
        self.assertTrue(weak)

    def test_well_named_primitive_is_semantically_typed(self):
        bucket, weak = classify_field("quantityField04", "short")
        self.assertEqual(bucket, "semantically_typed_bytes")
        self.assertFalse(weak)

    def test_pointer_to_real_class_well_named(self):
        bucket, weak = classify_field("selectedShipOrder", "TShipOrder *")
        self.assertEqual(bucket, "semantically_typed_bytes")
        self.assertFalse(weak)

    def test_pointer_to_real_class_weak_named(self):
        """A real pointee type but a weak (fieldXX) name -- bytes are typed, but
        the field is still flagged weak (a distinct axis from the byte bucket)."""
        bucket, weak = classify_field("field14", "TShipOrder *")
        self.assertEqual(bucket, "semantically_typed_bytes")
        self.assertTrue(weak)

    def test_by_value_aggregate_well_named(self):
        bucket, weak = classify_field("moveAnimSpriteSrcRectAC", "RECT")
        self.assertEqual(bucket, "semantically_typed_bytes")
        self.assertFalse(weak)


class ComputeInheritedBytesTests(unittest.TestCase):
    def test_single_base(self):
        layouts = {
            "Base": {"bases": {}, "fields": {}, "size": 8},
            "Derived": {"bases": {"Base": 0}, "fields": {}, "size": 12},
        }
        self.assertEqual(compute_inherited_bytes(layouts, "Derived"), 8)

    def test_no_base(self):
        layouts = {"Solo": {"bases": {}, "fields": {}, "size": 4}}
        self.assertEqual(compute_inherited_bytes(layouts, "Solo"), 0)

    def test_unknown_base_ignored(self):
        layouts = {"Derived": {"bases": {"ExternalBase": 0}, "fields": {}, "size": 12}}
        self.assertEqual(compute_inherited_bytes(layouts, "Derived"), 0)


class BuildReportIntegrationTests(unittest.TestCase):
    """End-to-end over a small synthetic repo tree (record_model.json +
    layout_oracle.json + a couple of source files for the reference index)."""

    def test_report_shape_and_ranking_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "build-msvc500/generated").mkdir(parents=True)
            (repo / "include/game").mkdir(parents=True)
            (repo / "src/game").mkdir(parents=True)

            record_model = {
                "Foo": {
                    "qualified_name": "Foo",
                    "tag": "struct",
                    "file": "include/game/Foo.h",
                    "bases": [],
                    "fields": [
                        {"name": "quantity", "type": "short", "is_bitfield": False, "array_count": 0},
                        {"name": "field04", "type": "int", "is_bitfield": False, "array_count": 0},
                        {"name": "pad08", "type": "unsigned char", "is_bitfield": False, "array_count": 0},
                    ],
                    "has_own_virtuals": False,
                },
            }
            layout_oracle = {
                "layouts": {
                    "Foo": {
                        "bases": {},
                        "fields": {
                            "quantity": {"offset": 0, "size": 2},
                            "field04": {"offset": 4, "size": 4},
                            "pad08": {"offset": 8, "size": 4},
                        },
                        "size": 12,
                    },
                },
            }
            (repo / "build-msvc500/generated/record_model.json").write_text(json.dumps(record_model))
            (repo / "build-msvc500/generated/layout_oracle.json").write_text(json.dumps(layout_oracle))
            (repo / "src/game/Foo.cpp").write_text(
                "void Foo::Bar() {\n"
                "  field04 = 1;\n"
                "  field04 += 2;\n"
                "  field04 += 3;\n"
                "}\n"
            )

            rows = build_report(repo)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["class"], "Foo")
            self.assertEqual(row["size"], 12)
            self.assertEqual(row["inherited_bytes"], 0)
            self.assertEqual(row["semantically_typed_bytes"], 2)  # quantity
            self.assertEqual(row["primitive_unknown_bytes"], 4)  # field04
            self.assertEqual(row["padding_bytes"], 4)  # pad08
            self.assertEqual(row["opaque_pointer_bytes"], 0)
            self.assertEqual(row["undefined_bytes"], 0)
            self.assertEqual(row["weak_field_count"], 2)  # field04, pad08
            # field04 appears 3 times (its own decl doesn't count -- decl is in
            # record_model.json/JSON, not the .cpp) in Foo.cpp; pad08 appears 0 times.
            self.assertEqual(row["reference_weight"], 3)


if __name__ == "__main__":
    unittest.main()
