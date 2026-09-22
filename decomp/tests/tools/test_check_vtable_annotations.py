"""Both-directions coverage for the // VTABLE annotation gate."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from tools.workflow.check_vtable_annotations import (
    CLASS_DECL_RE,
    FORWARD_DECL_RE,
    main,
    normalize_offset,
)


def run_gate(source: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.h"
        path.write_text(source, encoding="utf-8")
        argv = ["check_vtable_annotations", "--paths", str(path)]
        with mock.patch.object(sys, "argv", argv):
            return main()


class ClassDeclRegexTests(unittest.TestCase):
    def test_definition_lines_match(self) -> None:
        self.assertTrue(CLASS_DECL_RE.match("class TFoo : public TView {"))
        self.assertTrue(CLASS_DECL_RE.match("struct TBar {"))

    def test_forward_declaration_detected(self) -> None:
        line = "struct CRuntimeClass;"
        self.assertTrue(CLASS_DECL_RE.match(line))
        self.assertTrue(FORWARD_DECL_RE.match(line))

    def test_forward_decl_rejected_as_annotation_target(self) -> None:
        self.assertEqual(
            run_gate("// VTABLE: IMPERIALISM 0x00640000\nstruct TFwd;\n"), 1
        )

    def test_comment_between_marker_and_class_fails(self) -> None:
        self.assertEqual(
            run_gate(
                "// VTABLE: IMPERIALISM 0x00640000\n// note\nclass TFoo {};\n"
            ),
            1,
        )

    def test_marker_before_real_definition_passes(self) -> None:
        self.assertEqual(
            run_gate(
                "// VTABLE: IMPERIALISM 0x00640000\nclass TFoo : public TView {};\n"
            ),
            0,
        )


class NormalizeOffsetTests(unittest.TestCase):
    def test_lowercase_fold_only(self) -> None:
        self.assertEqual(normalize_offset("0x0064ABCD"), "0x0064abcd")


if __name__ == "__main__":
    unittest.main()
