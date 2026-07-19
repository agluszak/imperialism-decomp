"""Unit tests for the weak-pointer-type distinct-type inventory (Task 3).

Pure Python: no Ghidra. `classify_weak_pointer_type` and `_base_type_name` take
plain strings/sets; `build_inventory_rows` takes a plain occurrences dict as if
already collected from a live DB.
"""

import unittest

from tools.ghidra.weak_pointer_type_inventory import (
    _base_type_name,
    build_inventory_rows,
    classify_weak_pointer_type,
)


class BaseTypeNameTest(unittest.TestCase):
    def test_strips_pointer_and_elaborated_keyword(self):
        self.assertEqual(_base_type_name("class CDataExchange *"), "CDataExchange")
        self.assertEqual(_base_type_name("CDataExchange*"), "CDataExchange")

    def test_strips_reference(self):
        self.assertEqual(_base_type_name("CREATESTRUCT&"), "CREATESTRUCT")

    def test_strips_namespace_qualifier_to_last_segment(self):
        self.assertEqual(_base_type_name("turn_event_dialog::CityOrderSource*"),
                         "CityOrderSource")

    def test_bare_value_type_unchanged(self):
        self.assertEqual(_base_type_name("NationSlot"), "NationSlot")

    def test_struct_keyword_stripped(self):
        self.assertEqual(_base_type_name("struct CPrintInfo *"), "CPrintInfo")


class ClassifyWeakPointerTypeTest(unittest.TestCase):
    def test_stale_duplicate_wins_over_everything_else(self):
        # A real >1 name_count is a genuine collision regardless of what the
        # name otherwise looks like.
        cls, note = classify_weak_pointer_type(
            "CDataExchange", game_classes=set(), name_count=2)
        self.assertEqual(cls, "stale_duplicate")
        self.assertIn("2 distinct", note)

    def test_matches_known_game_class(self):
        cls, _note = classify_weak_pointer_type(
            "TZone", game_classes={"tzone", "tsimmgr"}, name_count=0)
        self.assertEqual(cls, "canonical_game_class_exists")

    def test_matches_known_mfc_type(self):
        cls, _note = classify_weak_pointer_type(
            "CView", game_classes=set(), name_count=0)
        self.assertEqual(cls, "canonical_mfc_type_exists")

    def test_matches_known_external_sdk_type(self):
        cls, _note = classify_weak_pointer_type(
            "CREATESTRUCT", game_classes=set(), name_count=0)
        self.assertEqual(cls, "missing_external_opaque_type")

    def test_matches_scalar_typedef_alias(self):
        cls, _note = classify_weak_pointer_type(
            "NationSlot", game_classes=set(), name_count=0)
        self.assertEqual(cls, "typedef_or_namespace_spelling_mismatch")

    def test_unknown_type_falls_back(self):
        cls, _note = classify_weak_pointer_type(
            "SomeNeverBeforeSeenType", game_classes=set(), name_count=0)
        self.assertEqual(cls, "genuinely_unknown")

    def test_case_insensitive_matching(self):
        cls, _note = classify_weak_pointer_type(
            "cview", game_classes=set(), name_count=0)
        self.assertEqual(cls, "canonical_mfc_type_exists")

    def test_game_class_match_is_case_insensitive_too(self):
        cls, _note = classify_weak_pointer_type(
            "TZONE", game_classes={"tzone"}, name_count=0)
        self.assertEqual(cls, "canonical_game_class_exists")


class BuildInventoryRowsTest(unittest.TestCase):
    def test_rows_sorted_by_occurrence_count_descending(self):
        occurrences = {
            ("opaque_pointee", "Rare"): {"count": 1, "example": "Foo::Bar", "name_count": 0},
            ("opaque_pointee", "Common"): {"count": 20, "example": "Baz::Qux", "name_count": 0},
        }
        rows = build_inventory_rows(occurrences, game_classes=set())
        self.assertEqual([r["type_text"] for r in rows], ["Common", "Rare"])

    def test_row_shape(self):
        occurrences = {
            ("unresolved", "NationSlot"): {"count": 4, "example": "TCountry::Foo", "name_count": 0},
        }
        rows = build_inventory_rows(occurrences, game_classes=set())
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["type_text"], "NationSlot")
        self.assertEqual(row["quality"], "unresolved")
        self.assertEqual(row["occurrence_count"], 4)
        self.assertEqual(row["example_function"], "TCountry::Foo")
        self.assertEqual(row["classification"], "typedef_or_namespace_spelling_mismatch")


if __name__ == "__main__":
    unittest.main()
