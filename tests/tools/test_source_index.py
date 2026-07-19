"""Tests for the source-marker index (tools.source_index).

The index is the authority for which original addresses manual source claims —
stub generation and gates derive from it, so scanning must see every marker kind
in both src/ and include/, and duplicate function-kind claims must be detected.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.source_index import find_duplicate_claims, scan_marker_claims


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
