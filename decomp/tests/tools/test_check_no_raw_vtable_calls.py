"""Both-directions coverage for the raw-vtable-call hard ban."""

from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from tools.workflow.check_no_raw_vtable_calls import count_patterns


def counts_for(source: str) -> dict[str, int]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.cpp"
        path.write_text(source, encoding="utf-8")
        return count_patterns(path)


class RawVtableCallTests(unittest.TestCase):
    def test_virtual_call_is_clean(self) -> None:
        counts = counts_for(
            "void f(TView* v) { v->DoDraw(); delete v; }\n"
        )
        self.assertEqual(sum(counts.values()), 0)

    def test_indexed_raw_vtable_call_flagged(self) -> None:
        counts = counts_for(
            "((void (__thiscall*)(TView*))(*reinterpret_cast<void***>(this))[4])(this);\n"
        )
        self.assertGreater(counts["raw_vtable_index"], 0)

    def test_vftable_subscript_flagged(self) -> None:
        counts = counts_for("auto p = vftable[3];\n")
        self.assertGreater(counts["vftable_index"], 0)

    def test_vcall_facade_flagged(self) -> None:
        counts = counts_for("void f() { VCall_DoDraw(this); }\n")
        self.assertGreater(counts["vcall_facade"], 0)

    def test_fn_typedef_cast_flagged(self) -> None:
        counts = counts_for("auto p = reinterpret_cast<DrawFn>(0x401000);\n")
        self.assertGreater(counts["fn_typedef_cast"], 0)


if __name__ == "__main__":
    unittest.main()
