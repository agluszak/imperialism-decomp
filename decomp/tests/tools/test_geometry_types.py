"""Tests for the MFC/native geometry boundary gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.workflow.check_geometry_types import (
    collect_geometry_casts,
    collect_policy_errors,
    iter_method_declarations,
)


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
    HEADER = "include/game/Fake.h"

    def _errors(self, header_text: str, allowlist: set | None = None) -> list[str]:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            header = root / self.HEADER
            header.parent.mkdir(parents=True)
            header.write_text(header_text, encoding="utf-8")
            return collect_policy_errors(
                root, (self.HEADER,), allowlist if allowlist is not None else set()
            )

    def test_mfc_geometry_passes(self):
        self.assertEqual(
            self._errors(
                "class TView {\npublic:\n"
                "  virtual void QueryBounds(CRect* boundsOut); // 0x4b 0x427290\n"
                "  virtual void SuperToLocal(CPoint* point);   // 0x51\n"
                "};\n"
            ),
            [],
        )

    def test_raw_point_in_method_decl_is_caught(self):
        errors = self._errors(
            "class TView {\npublic:\n"
            "  virtual void QueryBounds(CRect* boundsOut);\n"
            "  virtual char HandleMouseDown(const POINT& point, TToolboxEvent* event,\n"
            "                               POINT origin); // 0x46 0x48c450\n"
            "};\n"
        )
        self.assertTrue(any("HandleMouseDown" in e and "raw Win32 geometry" in e for e in errors))
        self.assertFalse(any("QueryBounds" in e for e in errors))

    def test_raw_rect_in_return_type_is_caught(self):
        errors = self._errors(
            "class TView {\npublic:\n"
            "  virtual void SuperToLocal(CPoint* point);\n"
            "  virtual RECT* GetQDExtent(CRect* rectOut);\n"
            "};\n"
        )
        self.assertTrue(any("GetQDExtent" in e for e in errors))

    def test_parser_sees_realistic_header_decl_format(self):
        # Verbatim declaration shapes from include/game/TView.h: multi-line decls,
        # trailing slot/address comments, default arguments, override suffixes,
        # DECLARE_DYNCREATE macro adjacency.
        text = (
            "// VTABLE: IMPERIALISM 0x649858\n"
            "class TView : public TEventHandler {\n"
            "public:\n"
            "  DECLARE_DYNCREATE(TView)\n"
            "  void Free() override;                  // 0x07\n"
            "  virtual void\n"
            "  HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,\n"
            "                                                      RgnHandle hitArg); // 0x35 0x48c080\n"
            "  virtual void TranslatePointToParentChain4D(CPoint* point = 0); // 0x4d 0x48ba80\n"
            "  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event,\n"
            "                             CPoint origin); // 0x48 0x48c590\n"
            "  virtual void ZoomByUser(const CPoint& point, short partCode);\n"
            "};\n"
            "ASSERT_SIZE(TView, 0x60);\n"
        )
        names = [name for name, _ in iter_method_declarations(text)]
        for expected in (
            "Free",
            "HandleCursorHoverSelectionByChildHitTestAndFallback",
            "TranslatePointToParentChain4D",
            "HandleMouseUp",
            "ZoomByUser",
        ):
            self.assertIn(expected, names)
        self.assertEqual(self._errors(text), [])

    def test_allowlist_permits_verified_boundary_method(self):
        text = (
            "class TView {\npublic:\n"
            "  virtual void QueryBounds(CRect* boundsOut);\n"
            "  virtual void Draw(RECT* clipRect); // 0x44\n"
            "};\n"
        )
        self.assertTrue(self._errors(text))
        self.assertEqual(self._errors(text, allowlist={(self.HEADER, "Draw")}), [])

    def test_stale_allowlist_entry_is_reported(self):
        errors = self._errors(
            "class TView {\npublic:\n  virtual void Draw(CRect* clipRect);\n};\n",
            allowlist={(self.HEADER, "Draw")},
        )
        self.assertTrue(any("stale RAW_GEOMETRY_ALLOWLIST" in e for e in errors))

    def test_header_without_mfc_geometry_decls_is_parser_drift(self):
        errors = self._errors("class TView {\npublic:\n  void Free();\n};\n")
        self.assertTrue(any("drifted" in e for e in errors))

    def test_current_tree_passes(self):
        repo_root = Path(__file__).resolve().parents[2]
        self.assertEqual(collect_policy_errors(repo_root), [])


if __name__ == "__main__":
    unittest.main()
