"""Tests for the dual-use / raw pointer<->int member-storage gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.workflow.check_dual_use import collect_offenders


def _offenders(text: str) -> set[str]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        src = root / "src" / "game"
        src.mkdir(parents=True)
        (src / "Fake.cpp").write_text(text, encoding="utf-8")
        found = collect_offenders([str(src)], root)
    return {sig.split(":", 1)[0] for _, sig in found}


class TestTerminology(unittest.TestCase):
    def test_banned_prose_flagged(self):
        for phrase in (
            "// this is a dual-use slot",
            "// dual-purpose per the discriminator",
            "// dual slot handling",
            "// +0x10 reused as a running offset",
            "// treated as both pointer and int",
        ):
            self.assertIn("term", _offenders(phrase), phrase)

    def test_clean_prose_not_flagged(self):
        self.assertEqual(_offenders("// a normal typed pointer field\nint x;"), set())

    def test_unresolved_marker_exempts(self):
        # The sanctioned honest-provisional state is not an offender.
        text = (
            "// UNRESOLVED_FIELD_ATTRIBUTION: +0x30 is a pointer here, a scalar in the bar;\n"
            "// do NOT relabel this dual-purpose until proven.\n"
            "int field30;\n"
        )
        self.assertEqual(_offenders(text), set())


class TestPointerIntCasts(unittest.TestCase):
    def test_ptr_to_int_field_store_flagged(self):
        self.assertIn("ptr2int", _offenders("this->field98 = reinterpret_cast<int>(control);"))

    def test_int_field_to_ptr_flagged(self):
        self.assertIn(
            "int2ptr",
            _offenders("auto* p = reinterpret_cast<TView*>(selected->field30);"),
        )

    def test_pointer_as_arg_not_flagged(self):
        # Passing a pointer as an int argument is a separate accepted pattern, not a member store.
        self.assertEqual(_offenders("Dispatch(reinterpret_cast<int>(&evt));"), set())

    def test_unresolved_window_exempts_cast(self):
        text = (
            "// UNRESOLVED_FIELD_ATTRIBUTION: +0x30 reading conflicts; see evidence.\n"
            "TView* m = reinterpret_cast<TView*>(selected->field30);\n"
        )
        self.assertEqual(_offenders(text), set())


if __name__ == "__main__":
    unittest.main()
