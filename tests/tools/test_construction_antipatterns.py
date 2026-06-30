#!/usr/bin/env python3
"""Tests for tools.workflow.check_construction_antipatterns."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.workflow.check_construction_antipatterns import (
    PATTERNS,
    count_patterns,
    is_generated,
    read_baseline,
    write_baseline,
)


class IsGeneratedTests(unittest.TestCase):
    def test_ghidra_autogen_path(self) -> None:
        self.assertTrue(is_generated("src/ghidra_autogen/SomeFile.cpp"))

    def test_autogen_stubs_path(self) -> None:
        self.assertTrue(is_generated("src/autogen/stubs/Stub.cpp"))

    def test_manual_path(self) -> None:
        self.assertFalse(is_generated("src/game/TCity.cpp"))

    def test_include_path(self) -> None:
        self.assertFalse(is_generated("include/game/TCity.h"))


class PatternDetectionTests(unittest.TestCase):
    def _write_temp(self, content: str) -> Path:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".cpp", delete=False, encoding="utf-8")
        f.write(content)
        f.close()
        return Path(f.name)

    def test_detects_inline_asm(self) -> None:
        path = self._write_temp("void foo() { __asm { nop } }")
        counts = count_patterns(path)
        self.assertGreater(counts["inline_asm"], 0)
        path.unlink()

    def test_detects_asm_keyword(self) -> None:
        path = self._write_temp("void foo() { _asm { int 3 } }")
        counts = count_patterns(path)
        self.assertGreater(counts["inline_asm"], 0)
        path.unlink()

    def test_detects_placement_new_this(self) -> None:
        path = self._write_temp("new (this) TBase();")
        counts = count_patterns(path)
        self.assertGreater(counts["placement_new_this"], 0)
        path.unlink()

    def test_detects_manual_vptr_write(self) -> None:
        path = self._write_temp("*(void**)this = &g_vtbl_TFoo;")
        counts = count_patterns(path)
        self.assertGreater(counts["manual_vptr_write"], 0)
        path.unlink()

    def test_detects_thiscall_cast(self) -> None:
        path = self._write_temp('reinterpret_cast<void(__thiscall*)(TView*, int)>(fn)(this, x);')
        counts = count_patterns(path)
        self.assertGreater(counts["thiscall_cast"], 0)
        path.unlink()

    def test_detects_bridge_name(self) -> None:
        path = self._write_temp("ConstructTBaseAtThis(this);")
        counts = count_patterns(path)
        self.assertGreater(counts["bridge_name"], 0)
        path.unlink()

    def test_detects_vcall_runtime_bridge(self) -> None:
        path = self._write_temp("VCall_BaseCtorRuntime(this);")
        counts = count_patterns(path)
        self.assertGreater(counts["bridge_name"], 0)
        path.unlink()

    def test_detects_and_maybe_free_bridge(self) -> None:
        path = self._write_temp("DestructTFooAndMaybeFree(this, flag);")
        counts = count_patterns(path)
        self.assertGreater(counts["bridge_name"], 0)
        path.unlink()

    def test_detects_operator_new(self) -> None:
        path = self._write_temp("void* p = operator new(sizeof(TFoo));")
        counts = count_patterns(path)
        self.assertGreater(counts["operator_new_delete"], 0)
        path.unlink()

    def test_clean_code_has_zero_counts(self) -> None:
        path = self._write_temp("int x = 5;\nvoid Foo() { return; }\n")
        counts = count_patterns(path)
        self.assertEqual(sum(counts.values()), 0)
        path.unlink()

    def test_strips_generated_blocks(self) -> None:
        content = "\n".join([
            "int clean();",
            "// === BEGIN GENERATED (TFoo) - refreshed by `just gen-class TFoo`; do not hand-edit ===",
            "ConstructTBaseAtThis(this);",
            "// === END GENERATED (TFoo) ===",
            "int more_clean();",
        ])
        path = self._write_temp(content)
        counts = count_patterns(path)
        self.assertEqual(counts["bridge_name"], 0)
        path.unlink()


class BaselineRoundtripTests(unittest.TestCase):
    def test_write_and_read_baseline(self) -> None:
        data = {
            "src/game/TCity.cpp": {"inline_asm": 0, "placement_new_this": 1, "manual_vptr_write": 0,
                                    "thiscall_cast": 0, "bridge_name": 2, "operator_new_delete": 0},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            path = Path(f.name)

        write_baseline(path, data)
        loaded = read_baseline(path)
        self.assertIn("src/game/TCity.cpp", loaded)
        self.assertEqual(loaded["src/game/TCity.cpp"]["placement_new_this"], 1)
        self.assertEqual(loaded["src/game/TCity.cpp"]["bridge_name"], 2)
        path.unlink()

    def test_missing_baseline_returns_empty(self) -> None:
        result = read_baseline(Path("/nonexistent/baseline.csv"))
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
