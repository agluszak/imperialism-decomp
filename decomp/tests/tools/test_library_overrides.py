#!/usr/bin/env python3
"""Tests for library-identity markers and their symbols overlay."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.generate_symbols import generate
from tools.source_model import build_model
from tools.workflow.check_library_identity import (
    IdentityCheck,
    check_override,
    prototype_declares_name,
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class StructuredMarkerTests(unittest.TestCase):
    def test_parses_name_symbol_prototype(self) -> None:
        repo = Path(tempfile.mkdtemp())
        _write(
            repo / "src" / "lib.cpp",
            "// LIBRARY: IMPERIALISM 0x005e83f0\n"
            "// name: rand\n"
            "// symbol: _rand\n"
            "// prototype: int __cdecl rand(void)\n",
        )
        (repo / "include").mkdir(exist_ok=True)
        claim = build_model(repo).functions[0x5E83F0]
        self.assertEqual(claim.kind, "LIBRARY")
        self.assertEqual(claim.name, "rand")
        self.assertEqual(claim.symbol, "_rand")
        self.assertEqual(claim.prototype, "int __cdecl rand(void)")


class ApplySymbolsTests(unittest.TestCase):
    def _repo(self, inventory_body: str, marker: str) -> Path:
        repo = Path(tempfile.mkdtemp()) / "repo"
        (repo / "config").mkdir(parents=True)
        (repo / "include").mkdir()
        _write(
            repo / "config" / "original_entities.csv",
            "address|name|symbol|size|type|prototype|provenance\n" + inventory_body,
        )
        _write(repo / "src" / "lib.cpp", marker)
        return repo

    def test_overlay_rewrites_invented_name(self) -> None:
        repo = self._repo(
            "5e83f0|GenerateThreadLocalRandom15||45|function|"
            "undefined GenerateThreadLocalRandom15()|\n",
            "// LIBRARY: IMPERIALISM 0x005e83f0\n"
            "// name: rand\n"
            "// symbol: _rand\n"
            "// prototype: int __cdecl rand(void)\n",
        )
        out = generate(repo, "IMPERIALISM", "config/original_entities.csv", repo / "gen")
        row = _row(out, 0x5E83F0)
        self.assertEqual(row["name"], "rand")
        self.assertEqual(row["symbol"], "_rand")
        self.assertEqual(row["prototype"], "int __cdecl rand(void)")
        inv_row = _row(repo / "config" / "original_entities.csv", 0x5E83F0)
        self.assertEqual(inv_row["name"], "GenerateThreadLocalRandom15")

    def test_overlay_adds_missing_row(self) -> None:
        repo = self._repo(
            "400000|other||4|function|undefined other()|\n",
            "// LIBRARY: IMPERIALISM 0x005e83f0\n"
            "// name: rand\n"
            "// symbol: _rand\n"
            "// prototype: int __cdecl rand(void)\n",
        )
        out = generate(repo, "IMPERIALISM", "config/original_entities.csv", repo / "gen")
        row = _row(out, 0x5E83F0)
        self.assertIsNotNone(row)
        self.assertEqual(row["provenance"], "library_identity_marker")

    def test_overlay_is_idempotent(self) -> None:
        repo = self._repo(
            "5e83f0|GenerateThreadLocalRandom15||45|function|"
            "undefined GenerateThreadLocalRandom15()|\n",
            "// LIBRARY: IMPERIALISM 0x005e83f0\n"
            "// name: rand\n"
            "// symbol: _rand\n"
            "// prototype: int __cdecl rand(void)\n",
        )
        out1 = generate(repo, "IMPERIALISM", "config/original_entities.csv", repo / "gen")
        first = out1.read_text(encoding="utf-8")
        out2 = generate(repo, "IMPERIALISM", "config/original_entities.csv", repo / "gen")
        self.assertEqual(first, out2.read_text(encoding="utf-8"))


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ov = IdentityCheck(
            address=0x5E83F0,
            name="rand",
            symbol="_rand",
            prototype="int __cdecl rand(void)",
            kind="LIBRARY",
        )

    def test_prototype_declares_name(self) -> None:
        self.assertTrue(prototype_declares_name("int __cdecl rand(void)", "rand"))
        self.assertFalse(prototype_declares_name("int __cdecl foo(void)", "rand"))
        self.assertTrue(
            prototype_declares_name("void operator delete(void*)", "CObject::operator delete")
        )

    def test_passes_when_applied(self) -> None:
        symbols = {
            0x5E83F0: {
                "name": "rand",
                "symbol": "_rand",
                "prototype": "int __cdecl rand(void)",
                "type": "function",
            }
        }
        self.assertEqual(check_override(self.ov, symbols, {0x5E83F0: "library"}), [])

    def test_fails_on_name_drift(self) -> None:
        symbols = {
            0x5E83F0: {
                "name": "GenerateThreadLocalRandom15",
                "symbol": "",
                "prototype": "undefined GenerateThreadLocalRandom15()",
                "type": "function",
            }
        }
        problems = check_override(self.ov, symbols, {0x5E83F0: "library"})
        self.assertTrue(any("name=" in p for p in problems))
        self.assertTrue(any("symbol=" in p for p in problems))

    def test_fails_when_not_library_owned(self) -> None:
        symbols = {
            0x5E83F0: {
                "name": "rand",
                "symbol": "_rand",
                "prototype": "int __cdecl rand(void)",
                "type": "function",
            }
        }
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
