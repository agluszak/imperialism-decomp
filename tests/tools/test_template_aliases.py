#!/usr/bin/env python3
"""Unit tests for the fold-aware equivalence-metadata loader (bd 5jjn.1)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.common.template_aliases import (
    CLASS_DUPLICATE_EMISSION,
    CLASS_FOLDED_SYMBOL_GROUP,
    CLASS_LIBRARY_CALLEE_ALIAS,
    load_alias_rows,
    load_aliases,
)


def write_csv(content: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(
        "w", suffix=".csv", delete=False, encoding="utf-8"
    )
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


class TestLoadAliasRows(unittest.TestCase):
    def test_both_classes_load(self) -> None:
        path = write_csv(
            "# comment\n"
            "0x00426ec0|0x00479b00|?AddTail@X@Z|per_tu_duplicate\n"
            "0x00430380|0x0048a9d0|TTreatiesView::~TTreatiesView|folded_symbol_group\n"
            "0x0049eb00|0x006057a7|??0CString@@QAE@ABV0@@Z|library_callee_alias\n"
        )
        rows, errors = load_alias_rows(path)
        self.assertEqual(errors, [])
        self.assertEqual(
            rows,
            [
                (0x426EC0, 0x479B00, "?AddTail@X@Z", "per_tu_duplicate"),
                (
                    0x430380,
                    0x48A9D0,
                    "TTreatiesView::~TTreatiesView",
                    "folded_symbol_group",
                ),
                (
                    0x49EB00,
                    0x6057A7,
                    "??0CString@@QAE@ABV0@@Z",
                    "library_callee_alias",
                ),
            ],
        )

    def test_unknown_classification_rejected(self) -> None:
        path = write_csv("0x1000|0x2000|Name|merely_similar\n")
        rows, errors = load_alias_rows(path)
        self.assertEqual(rows, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("unknown classification", errors[0])

    def test_duplicate_alias_and_self_alias_rejected(self) -> None:
        path = write_csv(
            "0x1000|0x2000|A|per_tu_duplicate\n"
            "0x1000|0x3000|B|per_tu_duplicate\n"
            "0x4000|0x4000|C|folded_symbol_group\n"
        )
        rows, errors = load_alias_rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(errors), 2)

    def test_class_filtering(self) -> None:
        path = write_csv(
            "0x1000|0x2000|A|per_tu_duplicate\n"
            "0x3000|0x4000|B|folded_symbol_group\n"
            "0x5000|0x6000|C|library_callee_alias\n"
        )
        all_aliases, _ = load_aliases(path)
        self.assertEqual(
            all_aliases,
            {0x1000: 0x2000, 0x3000: 0x4000, 0x5000: 0x6000},
        )
        dup, _ = load_aliases(path, equivalence_class=CLASS_DUPLICATE_EMISSION)
        self.assertEqual(dup, {0x1000: 0x2000})
        folded, _ = load_aliases(path, equivalence_class=CLASS_FOLDED_SYMBOL_GROUP)
        self.assertEqual(folded, {0x3000: 0x4000})
        library, _ = load_aliases(
            path, equivalence_class=CLASS_LIBRARY_CALLEE_ALIAS
        )
        self.assertEqual(library, {0x5000: 0x6000})

    def test_missing_file_is_empty(self) -> None:
        aliases, errors = load_aliases(Path("/nonexistent/aliases.csv"))
        self.assertEqual(aliases, {})
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
