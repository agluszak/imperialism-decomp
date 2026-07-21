"""Tests for the MFC/native geometry boundary gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.workflow.check_geometry_types import collect_geometry_casts, collect_policy_errors


def _casts(text: str) -> set[str]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        src = root / "src" / "game"
        src.mkdir(parents=True)
        (src / "Fake.cpp").write_text(text, encoding="utf-8")
        found = collect_geometry_casts([str(src)], root)
    return {offender.split(":", 1)[1] for _, offender in found}


class TestGeometryCasts(unittest.TestCase):
    def test_reinterpret_geometry_casts_fail(self):
        for text in (
            "auto p = reinterpret_cast<CPoint*>(raw);",
            "auto p = reinterpret_cast<const POINT*>(raw);",
            "auto r = reinterpret_cast<CRect*>(raw);",
            "auto r = reinterpret_cast<const RECT*>(raw);",
        ):
            self.assertTrue(_casts(text), text)

    def test_const_geometry_cast_fails(self):
        self.assertTrue(_casts("QueryBounds(const_cast<RECT*>(bounds));"))

    def test_c_style_geometry_cast_fails(self):
        self.assertTrue(_casts("Use((POINT*)payload);"))

    def test_implicit_conversion_and_void_cast_are_allowed(self):
        self.assertEqual(_casts("PtInRect(&rect, point);"), set())
        self.assertEqual(_casts("CPoint* point = static_cast<CPoint*>(payload);"), set())

    def test_raw_buffer_marker_allows_local_cast(self):
        text = (
            "// GEOMETRY_RAW_BUFFER: count followed by packed POINT records.\n"
            "Use(reinterpret_cast<POINT*>(words + 2));\n"
        )
        self.assertEqual(_casts(text), set())

    def test_marker_does_not_exempt_distant_cast(self):
        text = (
            "// GEOMETRY_RAW_BUFFER: one local packed payload.\n"
            "int a;\nint b;\nint c;\nint d;\n"
            "Use(reinterpret_cast<POINT*>(other));\n"
        )
        self.assertTrue(_casts(text))


class TestGeometryPolicy(unittest.TestCase):
    def _errors(self, declaration: str, expected: str = "CRect") -> list[str]:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            header = root / "include" / "game" / "Fake.h"
            header.parent.mkdir(parents=True)
            header.write_text(declaration, encoding="utf-8")
            return collect_policy_errors(
                root, {"include/game/Fake.h": {"QueryBounds": expected}}
            )

    def test_curated_api_accepts_mfc_geometry(self):
        self.assertEqual(self._errors("void QueryBounds(CRect* bounds);"), [])

    def test_curated_api_rejects_native_geometry(self):
        errors = self._errors("void QueryBounds(RECT* bounds);")
        self.assertTrue(any("must use CRect" in error for error in errors))
        self.assertTrue(any("drifts back" in error for error in errors))

    def test_curated_api_must_have_one_declaration(self):
        self.assertTrue(self._errors("void Other(CRect* bounds);"))
        self.assertTrue(
            self._errors(
                "void QueryBounds(CRect* first); void QueryBounds(CRect* second);"
            )
        )


if __name__ == "__main__":
    unittest.main()
