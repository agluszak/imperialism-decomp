"""Tests for the central source model (tools.source_model).

The index is the authority for which original addresses manual source claims —
stub generation and gates derive from it, so scanning must see every marker kind
in both src/ and include/, and duplicate function-kind claims must be detected.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.source_model import find_duplicate_claims, scan_marker_claims


def _repo(tree: dict[str, str]) -> Path:
    td = tempfile.mkdtemp()
    root = Path(td)
    for rel, text in tree.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


class TestScanMarkerClaims(unittest.TestCase):
    def test_all_marker_kinds_claim(self):
        root = _repo({
            "src/game/A.cpp": (
                "// FUNCTION: IMPERIALISM 0x00401000\nvoid A() {}\n"
                "// LIBRARY: IMPERIALISM 0x00402000\nvoid L() {}\n"
            ),
            "include/game/A.h": (
                "// SYNTHETIC: IMPERIALISM 0x00403000\n"
                "// TEMPLATE: IMPERIALISM 0x00404000\n"
                "// STUB: IMPERIALISM 0x00405000\n"
            ),
        })
        claims = scan_marker_claims(root, "IMPERIALISM")
        got = {(c.address, c.kind) for c in claims}
        self.assertEqual(got, {
            (0x401000, "FUNCTION"),
            (0x402000, "LIBRARY"),
            (0x403000, "SYNTHETIC"),
            (0x404000, "TEMPLATE"),
            (0x405000, "STUB"),
        })

    def test_generated_dirs_are_excluded(self):
        root = _repo({
            "src/game/A.cpp": "// FUNCTION: IMPERIALISM 0x00401000\nvoid A() {}\n",
            "src/ghidra_autogen/B.cpp": "// FUNCTION: IMPERIALISM 0x00409000\n",
        })
        claims = scan_marker_claims(root, "IMPERIALISM")
        self.assertEqual({c.address for c in claims}, {0x401000})

    def test_other_targets_ignored(self):
        root = _repo({
            "src/game/A.cpp": "// FUNCTION: OTHERGAME 0x00401000\nvoid A() {}\n",
        })
        self.assertEqual(scan_marker_claims(root, "IMPERIALISM"), [])

    def test_duplicate_claims_detected(self):
        root = _repo({
            "src/game/A.cpp": "// FUNCTION: IMPERIALISM 0x00401000\nvoid A() {}\n",
            "src/game/B.cpp": "// FUNCTION: IMPERIALISM 0x00401000\nvoid B() {}\n",
        })
        claims = scan_marker_claims(root, "IMPERIALISM")
        dupes = find_duplicate_claims(claims)
        self.assertEqual(set(dupes), {0x401000})
        self.assertEqual(len(dupes[0x401000]), 2)

    def test_no_duplicates_for_distinct_addresses(self):
        root = _repo({
            "src/game/A.cpp": (
                "// FUNCTION: IMPERIALISM 0x00401000\nvoid A() {}\n"
                "// FUNCTION: IMPERIALISM 0x00401010\nvoid B() {}\n"
            ),
        })
        claims = scan_marker_claims(root, "IMPERIALISM")
        self.assertEqual(find_duplicate_claims(claims), {})


if __name__ == "__main__":
    unittest.main()


class TestDeclarationParsing(unittest.TestCase):
    def _model(self, tree):
        root = _repo(tree)
        from tools.source_model import build_model
        return build_model(root, "IMPERIALISM")

    def test_qualified_name_and_prototype(self):
        m = self._model({"src/game/A.cpp":
            "// FUNCTION: IMPERIALISM 0x00401000\n"
            "void TLaborPool::WriteTo(TStream* stream) {}\n"})
        c = m.functions[0x401000]
        self.assertEqual(c.name, "TLaborPool::WriteTo")
        self.assertEqual(c.prototype, "void TLaborPool::WriteTo(TStream* stream)")

    def test_free_function_name_is_first_class(self):
        # The old parser required '::' and dropped free functions to the inventory.
        m = self._model({"src/game/A.cpp":
            "// FUNCTION: IMPERIALISM 0x00401000\n"
            "int ShowOutOfMemoryErrorNewHandler(unsigned int n) { return 0; }\n"})
        self.assertEqual(m.functions[0x401000].name, "ShowOutOfMemoryErrorNewHandler")

    def test_multiline_declaration(self):
        m = self._model({"src/game/A.cpp":
            "// FUNCTION: IMPERIALISM 0x00401000\n"
            "void TFoo::Bar(int a,\n"
            "               int b) {\n"
            "}\n"})
        c = m.functions[0x401000]
        self.assertEqual(c.name, "TFoo::Bar")
        self.assertEqual(c.prototype, "void TFoo::Bar(int a, int b)")

    def test_synthetic_comment_name(self):
        m = self._model({"src/game/A.cpp":
            "// SYNTHETIC: IMPERIALISM 0x00401000\n"
            "// CAmbitDocument::GetRuntimeClass\n"})
        self.assertEqual(m.functions[0x401000].name, "CAmbitDocument::GetRuntimeClass")

    def test_library_mangled_comment_is_symbol_not_name(self):
        m = self._model({"src/game/A.cpp":
            "// LIBRARY: IMPERIALISM 0x00401000\n"
            "// ___ld12tod\n"})
        c = m.functions[0x401000]
        self.assertEqual(c.name, "")
        self.assertEqual(c.symbol, "___ld12tod")

    def test_vtable_and_global(self):
        m = self._model({"include/game/T.h":
            "// VTABLE: IMPERIALISM 0x00650a08\n"
            "class TLongintList : public CObject {\n};\n",
            "src/game/g.cpp":
            "// GLOBAL: IMPERIALISM 0x006a2158\n"
            "TDisplayMgr* g_pDisplayMgr = 0;\n"})
        self.assertEqual(m.vtables[0x650a08], "TLongintList")
        self.assertEqual(m.globals[0x6a2158], "g_pDisplayMgr")
