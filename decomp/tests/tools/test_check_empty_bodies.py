"""Tests for the silent no-op detector, including the bd-kwee audit extensions
(trivial-return bodies over big originals, ctor missing derived-field init)."""

from __future__ import annotations

import unittest
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

from tools.workflow.check_empty_bodies import (
    AUDIT_KINDS,
    VIOLATION_KINDS,
    baseline_file_is_initialized,
    counts_per_file,
    derived_store_offsets,
    is_empty_body,
    is_trivial_return_body,
    scan_file,
)

_CPP = Language(tree_sitter_cpp.language())


def _first_body(source: str):
    tree = Parser(_CPP).parse(source.encode())
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "function_definition":
            return node.child_by_field_name("body")
    raise AssertionError("no function definition in fixture")


def _scan(tmp: Path, source: str, symbols: dict[str, tuple[int, int]]):
    path = tmp / "Fake.cpp"
    path.write_text(source, encoding="utf-8")
    addr_sizes = {addr: size for addr, size in symbols.values()}
    return scan_file(path, symbols, addr_sizes, max_noop_size=16, ctx=None)


class TestTrivialReturnParse(unittest.TestCase):
    def test_return_literal_detected(self):
        for body in ("return 0;", "return 1;", "return -1;", "return false;"):
            self.assertTrue(
                is_trivial_return_body(_first_body(f"int F() {{ {body} }}")), body
            )

    def test_real_bodies_not_detected(self):
        for body in ("return x;", "return Compute();", "int y = 0; return y;", ""):
            self.assertFalse(
                is_trivial_return_body(_first_body(f"int F() {{ {body} }}")), body
            )

    def test_empty_body_is_not_trivial_return(self):
        node = _first_body("void F() { }")
        self.assertTrue(is_empty_body(node))
        self.assertFalse(is_trivial_return_body(node))


class TestEmptyBaseline(unittest.TestCase):
    def test_header_only_baseline_is_initialized_zero_floor(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "baseline.csv"
            path.write_text("file|empty_but_big|empty_unmarked|empty_unresolved|noop_contradicted\n")
            self.assertTrue(baseline_file_is_initialized(path))

    def test_missing_or_empty_baseline_is_not_initialized(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "baseline.csv"
            self.assertFalse(baseline_file_is_initialized(path))
            path.write_text("")
            self.assertFalse(baseline_file_is_initialized(path))


class TestTrivialReturnClassification(unittest.TestCase):
    SOURCE = (
        "// FUNCTION: IMPERIALISM 0x00500000\n"
        "int TFoo::Compute() {\n"
        "  return 0;\n"
        "}\n"
    )

    def test_big_original_flagged(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            findings = _scan(Path(d), self.SOURCE, {"TFoo::Compute": (0x500000, 400)})
        kinds = {f["kind"] for f in findings}
        self.assertIn("trivial_return_but_big", kinds)

    def test_tiny_original_not_flagged(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            findings = _scan(Path(d), self.SOURCE, {"TFoo::Compute": (0x500000, 6)})
        self.assertEqual(findings, [])

    def test_library_marker_exempt(self):
        import tempfile

        source = self.SOURCE.replace("FUNCTION", "LIBRARY")
        with tempfile.TemporaryDirectory() as d:
            findings = _scan(Path(d), source, {"TFoo::Compute": (0x500000, 400)})
        self.assertEqual(findings, [])

    def test_promoted_kind_is_counted_by_the_ratchet(self):
        """bd rziq: trivial_return_but_big is a gated violation, not audit-only."""
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            findings = _scan(Path(d), self.SOURCE, {"TFoo::Compute": (0x500000, 400)})
            counts = counts_per_file(findings, Path(d))
        self.assertEqual(
            [row["trivial_return_but_big"] for row in counts.values()], [1]
        )
        self.assertIn("trivial_return_but_big", VIOLATION_KINDS)
        self.assertNotIn("trivial_return_but_big", AUDIT_KINDS)
        self.assertTrue(set(AUDIT_KINDS).isdisjoint(VIOLATION_KINDS))

    def test_audit_only_kind_still_excluded_from_ratchet(self):
        """ctor_missing_derived_init stays outside the baseline until it is triaged."""
        import tempfile

        finding = {"kind": "ctor_missing_derived_init", "file": "src/game/TFoo.cpp"}
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(counts_per_file([finding], Path(d)), {})


class TestDerivedStoreOffsets(unittest.TestCase):
    # mov esi, ecx ; mov dword [esi], 0x1000 (vptr) ;
    # mov word [esi+0x60], ax ; mov dword [esi+0x94], 7 ; ret
    CODE = bytes.fromhex(
        "8bf1"  # mov esi, ecx
        "c70600100000"  # mov dword ptr [esi], 0x1000
        "66894660"  # mov word ptr [esi+0x60], ax
        "c7869400000007000000"  # mov dword ptr [esi+0x94], 7
        "c3"
    )

    def test_stores_beyond_base_flagged(self):
        self.assertEqual(derived_store_offsets(self.CODE, 0x500000, 0x90), [0x94])

    def test_base_region_stores_ignored(self):
        self.assertEqual(derived_store_offsets(self.CODE, 0x500000, 0x98), [])

    def test_alias_lost_after_clobber(self):
        # mov esi, ecx ; mov esi, eax (clobber) ; mov dword [esi+0x94], 7 ; ret
        code = bytes.fromhex("8bf1" "8bf0" "c7869400000007000000" "c3")
        self.assertEqual(derived_store_offsets(code, 0x500000, 0x10), [])

    def test_call_clobbers_ecx_alias(self):
        # call +0 ; mov dword [ecx+0x94], 7 ; ret — after a call ECX is dead
        code = bytes.fromhex("e800000000" "c7819400000007000000" "c3")
        self.assertEqual(derived_store_offsets(code, 0x500000, 0x10), [])


if __name__ == "__main__":
    unittest.main()
