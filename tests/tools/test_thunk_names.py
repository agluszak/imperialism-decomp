#!/usr/bin/env python3
"""Tests for tools.common.thunk_names."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.common.thunk_names import ThunkResolver, load_thunk_map, dump_thunk_map


class ThunkResolverTests(unittest.TestCase):
    def test_rewrites_thunk_name(self) -> None:
        resolver = ThunkResolver({"thunk_DoWork": "TWorker::DoWork"})
        result = resolver.resolve("thunk_DoWork(this);")
        self.assertIn("TWorker::DoWork", result)
        self.assertNotIn("thunk_DoWork", result)

    def test_rewrites_qualified_thunk_name(self) -> None:
        resolver = ThunkResolver({"thunk_Foo": "TBar::Foo"})
        result = resolver.resolve("TBaz::thunk_Foo(this);")
        self.assertIn("TBar::Foo", result)
        self.assertNotIn("thunk_Foo", result)

    def test_rewrites_other_name_only_in_call_position(self) -> None:
        resolver = ThunkResolver({"CWnd": "CWnd::~CWnd"})
        result = resolver.resolve("CWnd(param);")
        self.assertIn("CWnd::~CWnd", result)

    def test_does_not_rewrite_already_qualified_other_name(self) -> None:
        resolver = ThunkResolver({"CWnd": "CWnd::~CWnd"})
        result = resolver.resolve("SomeClass::CWnd(param);")
        self.assertNotIn("CWnd::~CWnd::~CWnd", result)

    def test_does_not_rewrite_destructor_token(self) -> None:
        resolver = ThunkResolver({"CWnd": "CWnd::~CWnd"})
        result = resolver.resolve("~CWnd(param);")
        self.assertNotIn("CWnd::~CWnd", result)

    def test_empty_map_is_noop(self) -> None:
        resolver = ThunkResolver({})
        self.assertFalse(resolver)
        self.assertEqual(resolver.resolve("anything"), "anything")

    def test_identity_mapping_skipped(self) -> None:
        resolver = ThunkResolver({"Foo": "Foo"})
        self.assertFalse(resolver)

    def test_bool_true_when_active(self) -> None:
        resolver = ThunkResolver({"thunk_Foo": "Bar::Foo"})
        self.assertTrue(resolver)

    def test_multiple_thunks_in_same_text(self) -> None:
        resolver = ThunkResolver({
            "thunk_A": "TA::A",
            "thunk_B": "TB::B",
        })
        result = resolver.resolve("thunk_A(x); thunk_B(y);")
        self.assertIn("TA::A", result)
        self.assertIn("TB::B", result)
        self.assertNotIn("thunk_A", result)
        self.assertNotIn("thunk_B", result)


class LoadThunkMapTests(unittest.TestCase):
    def test_loads_from_csv(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("thunk_name|real_name\n")
            f.write("thunk_Foo|TBar::Foo\n")
            f.write("thunk_Baz|TQux::Baz\n")
            path = Path(f.name)

        result = load_thunk_map(path)
        self.assertEqual(result, {"thunk_Foo": "TBar::Foo", "thunk_Baz": "TQux::Baz"})
        path.unlink()

    def test_missing_file_returns_empty(self) -> None:
        result = load_thunk_map(Path("/nonexistent/thunk_map.csv"))
        self.assertEqual(result, {})

    def test_skips_identity_rows(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("thunk_name|real_name\n")
            f.write("Foo|Foo\n")
            f.write("thunk_Bar|TBar::Bar\n")
            path = Path(f.name)

        result = load_thunk_map(path)
        self.assertEqual(result, {"thunk_Bar": "TBar::Bar"})
        path.unlink()


class DumpThunkMapTests(unittest.TestCase):
    def test_deterministic_output(self) -> None:
        thunk_map = {"thunk_B": "TB::B", "thunk_A": "TA::A"}
        result = dump_thunk_map(thunk_map)
        lines = result.strip().split("\n")
        self.assertEqual(lines[0], "thunk_name|real_name")
        self.assertEqual(lines[1], "thunk_A|TA::A")
        self.assertEqual(lines[2], "thunk_B|TB::B")

    def test_roundtrip(self) -> None:
        original = {"thunk_Foo": "TBar::Foo", "thunk_Baz": "TQux::Baz"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write(dump_thunk_map(original))
            path = Path(f.name)

        loaded = load_thunk_map(path)
        self.assertEqual(loaded, original)
        path.unlink()


if __name__ == "__main__":
    unittest.main()
