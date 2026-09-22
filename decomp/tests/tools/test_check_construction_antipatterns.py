"""Both-directions coverage for the construction anti-pattern hard ban."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from tools.workflow.check_construction_antipatterns import count_patterns


def counts_for(source: str) -> dict[str, int]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.cpp"
        path.write_text(source, encoding="utf-8")
        return count_patterns(path)


class ConstructionAntipatternTests(unittest.TestCase):
    def test_clean_source_reports_zero(self) -> None:
        counts = counts_for(
            "class TThing : public TView {};\n"
            "void TThing::Update() { this->flags |= 1; }\n"
        )
        self.assertEqual(sum(counts.values()), 0)

    def test_placement_new_on_this_flagged(self) -> None:
        counts = counts_for("void f(TThing* t) { new (this) TThing(); }\n")
        self.assertGreater(counts["placement_new_this"], 0)

    def test_manual_vptr_write_flagged(self) -> None:
        counts = counts_for(
            "TThing::TThing() { *(void**)this = &g_vtbl_TThing; }\n"
        )
        self.assertGreater(counts["manual_vptr_write"], 0)

    def test_inline_asm_flagged(self) -> None:
        counts = counts_for("void f() { __asm mov eax, ecx }\n")
        self.assertGreater(counts["inline_asm"], 0)

    def test_thiscall_cast_flagged(self) -> None:
        counts = counts_for(
            "auto p = reinterpret_cast<void (__thiscall*)(void*)>(0x401000);\n"
        )
        self.assertGreater(counts["thiscall_cast"], 0)

    def test_bridge_name_flagged(self) -> None:
        counts = counts_for("void f() { DestructFooAndMaybeFree(x, 1); }\n")
        self.assertGreater(counts["bridge_name"], 0)

    def test_raw_this_offset_flagged(self) -> None:
        counts = counts_for(
            "int f() { return *(int*)(reinterpret_cast<char*>(this) + 0x10); }\n"
        )
        self.assertGreater(counts["raw_this_offset"], 0)

    def test_comment_lines_are_not_code(self) -> None:
        counts = counts_for("// *(void**)this = &g_vtbl_X in retail\n")
        self.assertEqual(counts["manual_vptr_write"], 0)


if __name__ == "__main__":
    unittest.main()
