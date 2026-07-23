#!/usr/bin/env python3
"""Tests for the structure-audit gate's duplicate-include detection."""

from __future__ import annotations

import unittest

from tools.workflow.check_structure_audit import duplicate_top_level_includes


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


if __name__ == "__main__":
    unittest.main()
