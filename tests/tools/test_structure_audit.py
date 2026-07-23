#!/usr/bin/env python3
"""Tests for the structure-audit gate's duplicate-include and alias-header detection."""

from __future__ import annotations

import unittest

from tools.workflow.check_structure_audit import (
    duplicate_top_level_includes,
    is_alias_header,
    is_annotation_only_tu,
)


class DuplicateIncludeTest(unittest.TestCase):
    def test_no_duplicates(self):
        text = '#include "a.h"\n#include "b.h"\n'
        self.assertEqual(duplicate_top_level_includes(text), [])

    def test_top_level_duplicate_flagged(self):
        text = '#include "a.h"\n#include "b.h"\n#include "a.h"\n'
        self.assertEqual(duplicate_top_level_includes(text), ['"a.h"'])

    def test_multiple_duplicates_sorted(self):
        text = '#include "b.h"\n#include "a.h"\n#include "b.h"\n#include "a.h"\n'
        self.assertEqual(duplicate_top_level_includes(text), ['"a.h"', '"b.h"'])

    def test_conditional_reinclude_not_flagged(self):
        # An include guarded by #if is a legitimate conditional re-include, not noise.
        text = '#include "a.h"\n#ifdef X\n#include "a.h"\n#endif\n'
        self.assertEqual(duplicate_top_level_includes(text), [])

    def test_angle_and_quote_are_distinct_keys(self):
        text = '#include <a.h>\n#include "a.h"\n'
        self.assertEqual(duplicate_top_level_includes(text), [])

    def test_nested_if_depth_tracking(self):
        # Two includes both inside (possibly nested) #if blocks are never top-level.
        text = '#if A\n#if B\n#include "a.h"\n#endif\n#include "a.h"\n#endif\n'
        self.assertEqual(duplicate_top_level_includes(text), [])


class AliasHeaderTest(unittest.TestCase):
    def test_class_reexport_alias_flagged(self):
        text = '#pragma once\n\n#include "game/TViewMgr.h"\n\ntypedef TViewMgr TUiRuntimeContext;\n'
        self.assertTrue(is_alias_header(text))

    def test_pure_single_include_wrapper_flagged(self):
        text = '#pragma once\n\n// Descriptive-name wrapper; the real class is TSimMgr.\n#include "game/TSimMgr.h"\n'
        self.assertTrue(is_alias_header(text))

    def test_domain_vocabulary_typedefs_not_flagged(self):
        # Scalar domain typedefs over one include are a vocabulary header, not an alias.
        text = '#pragma once\n\n#include "game/diplomacy_domain_types.h"\n\ntypedef short NationSlot;\ntypedef short NeedType;\n'
        self.assertFalse(is_alias_header(text))

    def test_umbrella_multi_include_not_flagged(self):
        text = '#pragma once\n#include "game/globals/a.h"\n#include "game/globals/b.h"\n'
        self.assertFalse(is_alias_header(text))

    def test_real_declarations_not_flagged(self):
        text = '#pragma once\n#include "game/TObject.h"\n\nclass TThing : public TObject {};\n'
        self.assertFalse(is_alias_header(text))


class AnnotationOnlyTuTest(unittest.TestCase):
    def test_marker_only_tu_flagged(self):
        text = (
            "// Identity markers for MFC CPtrList (library code; never ported).\n"
            "\n"
            "// LIBRARY: IMPERIALISM 0x005c1234\n"
            "// CPtrList::AddTail\n"
            "\n"
            "// SYNTHETIC: IMPERIALISM 0x005c5678\n"
            "// CPtrList::`scalar deleting destructor'\n"
        )
        self.assertTrue(is_annotation_only_tu(text))

    def test_markers_with_includes_and_pragmas_flagged(self):
        text = (
            '#include "game/global_data_tables.h"\n'
            "#pragma once\n"
            "// LIBRARY: IMPERIALISM 0x005c1234\n"
            "// _rand\n"
        )
        self.assertTrue(is_annotation_only_tu(text))

    def test_block_comment_only_flagged(self):
        text = "/* Historical notes\n   spanning lines. */\n\n// LIBRARY: IMPERIALISM 0x005c1234\n"
        self.assertTrue(is_annotation_only_tu(text))

    def test_function_definition_not_flagged(self):
        text = (
            "// FUNCTION: IMPERIALISM 0x004d3a60\n"
            "int TCivMgr::HandleAction(int action)\n"
            "{\n"
            "    return action + 1;\n"
            "}\n"
        )
        self.assertFalse(is_annotation_only_tu(text))

    def test_global_definition_not_flagged(self):
        text = '#include "game/global_data_tables.h"\n\nint g_thing = 5;\n'
        self.assertFalse(is_annotation_only_tu(text))

    def test_if0_code_conservatively_not_flagged(self):
        # Dead #if 0 code still counts as content; the generated #if 0 marker TU
        # lives in the build dir and is never scanned by this gate.
        text = "#if 0\nint dead(void) { return 0; }\n#endif\n"
        self.assertFalse(is_annotation_only_tu(text))

    def test_multiline_define_is_preprocessor_only(self):
        text = "#define HELPER(x) \\\n    ((x) + 1)\n// LIBRARY: IMPERIALISM 0x005c1234\n"
        self.assertTrue(is_annotation_only_tu(text))

    def test_empty_file_flagged(self):
        self.assertTrue(is_annotation_only_tu(""))


if __name__ == "__main__":
    unittest.main()
