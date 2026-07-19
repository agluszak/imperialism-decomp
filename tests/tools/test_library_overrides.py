#!/usr/bin/env python3
"""Tests for the reviewed MSVC500 library-identity override layer.

Covers the applier (tools.mfc.apply_library_overrides) and the semantic gate
(tools.workflow.check_library_identity), including the rand regression pin.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.generate_symbols import generate
from tools.mfc.apply_library_overrides import (
    apply_markers,
    load_overrides,
    render_marker_file,
)
from tools.mfc.apply_msvc500_library_region import SourceMarker
from tools.workflow.check_library_identity import check_override, prototype_declares_name

RAND_ROW = (
    "0x005e83f0|rand|_rand|int __cdecl rand(void)|libcmt|rand.obj|evidence_here"
)
HEADER = "address|name|symbol|prototype|library_family|object_member|evidence"


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class LoadOverridesTests(unittest.TestCase):
    def _overrides(self, body: str) -> Path:
        tmp = Path(tempfile.mkdtemp())
        return _write(tmp / "ov.csv", f"{HEADER}\n{body}\n")

    def test_parses_rand(self) -> None:
        overrides = load_overrides(self._overrides(RAND_ROW))
        self.assertEqual(len(overrides), 1)
        ov = overrides[0]
        self.assertEqual(ov.address, 0x005E83F0)
        self.assertEqual(ov.name, "rand")
        self.assertEqual(ov.symbol, "_rand")
        self.assertEqual(ov.prototype, "int __cdecl rand(void)")
        self.assertEqual(ov.object_member, "rand.obj")

    def test_duplicate_address_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            load_overrides(self._overrides(f"{RAND_ROW}\n{RAND_ROW}"))

    def test_missing_required_field_rejected(self) -> None:
        bad = "0x005e83f0|rand||int __cdecl rand(void)|libcmt|rand.obj|e"
        with self.assertRaises(SystemExit):
            load_overrides(self._overrides(bad))


class ApplySymbolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.overrides = load_overrides(
            _write(self.tmp / "ov.csv", f"{HEADER}\n{RAND_ROW}\n")
        )

    def _symbols(self, body: str) -> Path:
        return _write(
            self.tmp / "symbols.csv",
            "address|name|symbol|size|type|prototype|provenance\n" + body,
        )

    def _repo(self, inventory_body: str) -> Path:
        """A minimal repo tree: inventory + reviewed file + empty src/include."""
        repo = self.tmp / "repo"
        (repo / "config").mkdir(parents=True, exist_ok=True)
        (repo / "src").mkdir(exist_ok=True)
        (repo / "include").mkdir(exist_ok=True)
        _write(repo / "config" / "original_entities.csv",
               "address|name|symbol|size|type|prototype|provenance\n" + inventory_body)
        _write(repo / "config" / "reviewed_library_identities.csv",
               f"{HEADER}\n{RAND_ROW}\n")
        return repo

    def test_overlay_rewrites_invented_name(self) -> None:
        repo = self._repo(
            "5e83f0|GenerateThreadLocalRandom15||45|function|"
            "undefined GenerateThreadLocalRandom15()|\n"
        )
        out = generate(repo, "IMPERIALISM", "config/original_entities.csv",
                       repo / "gen")
        row = _row(out, 0x5E83F0)
        self.assertEqual(row["name"], "rand")
        self.assertEqual(row["symbol"], "_rand")
        self.assertEqual(row["prototype"], "int __cdecl rand(void)")
        # The committed inventory itself is untouched (raw; never merged).
        inv_row = _row(repo / "config" / "original_entities.csv", 0x5E83F0)
        self.assertEqual(inv_row["name"], "GenerateThreadLocalRandom15")

    def test_overlay_adds_missing_row(self) -> None:
        repo = self._repo("400000|other||4|function|undefined other()|\n")
        out = generate(repo, "IMPERIALISM", "config/original_entities.csv",
                       repo / "gen")
        row = _row(out, 0x5E83F0)
        self.assertIsNotNone(row)
        self.assertEqual(row["provenance"], "reviewed_library_identity")

    def test_overlay_is_idempotent(self) -> None:
        repo = self._repo(
            "5e83f0|GenerateThreadLocalRandom15||45|function|"
            "undefined GenerateThreadLocalRandom15()|\n"
        )
        out1 = generate(repo, "IMPERIALISM", "config/original_entities.csv",
                        repo / "gen")
        first = out1.read_text(encoding="utf-8")
        out2 = generate(repo, "IMPERIALISM", "config/original_entities.csv",
                        repo / "gen")
        self.assertEqual(first, out2.read_text(encoding="utf-8"))


class ApplyMarkersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.overrides = load_overrides(
            _write(self.tmp / "ov.csv", f"{HEADER}\n{RAND_ROW}\n")
        )
        self.marker_path = self.tmp / "library_msvc500_overrides.cpp"
        self.marker_rel = "src/game/library_msvc500_overrides.cpp"

    def test_adds_marker_when_absent(self) -> None:
        changes, changed = apply_markers(
            self.marker_path, self.overrides, {}, marker_rel=self.marker_rel, target="IMPERIALISM"
        )
        self.assertTrue(changed)
        text = self.marker_path.read_text()
        self.assertIn("// LIBRARY: IMPERIALISM 0x005e83f0", text)
        self.assertIn("// _rand", text)

    def test_skips_when_library_marker_elsewhere(self) -> None:
        existing = {0x5E83F0: SourceMarker(kind="LIBRARY", path="src/game/library_msvc500_fid.cpp")}
        changes, changed = apply_markers(
            self.marker_path, self.overrides, existing,
            marker_rel=self.marker_rel, target="IMPERIALISM",
        )
        # No new marker file content for this address (metadata-only override).
        self.assertNotIn("0x005e83f0", self.marker_path.read_text())

    def test_conflict_with_function_marker_raises(self) -> None:
        existing = {0x5E83F0: SourceMarker(kind="FUNCTION", path="src/game/Foo.cpp")}
        with self.assertRaises(SystemExit):
            apply_markers(
                self.marker_path, self.overrides, existing,
                marker_rel=self.marker_rel, target="IMPERIALISM",
            )


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.ov = load_overrides(_write(tmp / "ov.csv", f"{HEADER}\n{RAND_ROW}\n"))[0]

    def test_prototype_declares_name(self) -> None:
        self.assertTrue(prototype_declares_name("int __cdecl rand(void)", "rand"))
        self.assertFalse(prototype_declares_name("int __cdecl foo(void)", "rand"))
        # operator/dtor names are accepted structurally.
        self.assertTrue(prototype_declares_name("void operator delete(void*)", "CObject::operator delete"))

    def test_passes_when_applied(self) -> None:
        symbols = {0x5E83F0: {
            "name": "rand", "symbol": "_rand",
            "prototype": "int __cdecl rand(void)", "type": "function",
        }}
        ownership = {0x5E83F0: "library"}
        self.assertEqual(check_override(self.ov, symbols, ownership), [])

    def test_fails_on_name_drift(self) -> None:
        symbols = {0x5E83F0: {
            "name": "GenerateThreadLocalRandom15", "symbol": "",
            "prototype": "undefined GenerateThreadLocalRandom15()", "type": "function",
        }}
        problems = check_override(self.ov, symbols, {0x5E83F0: "library"})
        self.assertTrue(any("name=" in p for p in problems))
        self.assertTrue(any("symbol=" in p for p in problems))

    def test_fails_when_not_library_owned(self) -> None:
        symbols = {0x5E83F0: {
            "name": "rand", "symbol": "_rand",
            "prototype": "int __cdecl rand(void)", "type": "function",
        }}
        problems = check_override(self.ov, symbols, {0x5E83F0: "autogen"})
        self.assertTrue(any("ownership=" in p for p in problems))

    def test_fails_when_row_missing(self) -> None:
        problems = check_override(self.ov, {}, {})
        self.assertTrue(any("no symbols.csv row" in p for p in problems))


def _row(symbols_path: Path, address: int) -> dict[str, str] | None:
    from tools.common.pipe_csv import read_pipe_rows

    for row in read_pipe_rows(symbols_path):
        try:
            if int((row.get("address") or "0"), 16) == address:
                return row
        except ValueError:
            continue
    return None


if __name__ == "__main__":
    unittest.main()
