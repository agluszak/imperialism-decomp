"""Tests for the class-model projection PLANNER (pure Python, no Ghidra).

plan_components turns the semantic model + oracle layout into flat, offset-exact
component lists; its flattening/vptr/overlap behaviour decides what the Ghidra
apply writes, so it is pinned here.
"""

import unittest

from tools.ghidra.apply_class_model import plan_components


def _rec(bases=(), fields=(), virtuals=False):
    return {"bases": [{"type": b} for b in bases],
            "fields": [{"name": n, "type": t, "array_count": a} for n, t, a in fields],
            "has_own_virtuals": virtuals}


class PlanComponentsTest(unittest.TestCase):
    def test_simple_struct(self):
        model = {"Seapoint": _rec(fields=[("coord00", "int", 0), ("lo04", "int", 0)])}
        layouts = {"Seapoint": {"size": 8, "bases": {}, "fields": {
            "coord00": {"offset": 0, "size": 4}, "lo04": {"offset": 4, "size": 4}}}}
        size, comps, notes = plan_components("Seapoint", model, layouts, {})
        self.assertEqual(size, 8)
        self.assertEqual([(c[0], c[3]) for c in comps], [(0, "coord00"), (4, "lo04")])
        self.assertEqual(notes, [])

    def test_polymorphic_root_gets_vptr(self):
        model = {"TObject": _rec(fields=[("x", "int", 0)], virtuals=True)}
        layouts = {"TObject": {"size": 8, "bases": {}, "fields": {"x": {"offset": 4, "size": 4}}}}
        _s, comps, _n = plan_components("TObject", model, layouts, {})
        self.assertEqual(comps[0], (0, 4, "vptr", "vfptr", "void**"))

    def test_game_base_flattened_with_inherited_vptr(self):
        model = {
            "TBase": _rec(fields=[("a", "short", 0)], virtuals=True),
            "TDerived": _rec(bases=["TBase"], fields=[("b", "int", 0)], virtuals=True),
        }
        layouts = {
            "TBase": {"size": 8, "bases": {}, "fields": {"a": {"offset": 4, "size": 2}}},
            "TDerived": {"size": 12, "bases": {"TBase": 0},
                         "fields": {"b": {"offset": 8, "size": 4}}},
        }
        _s, comps, notes = plan_components("TDerived", model, layouts, {})
        # vptr comes ONCE via the flattened base; derived's own-virtuals must not
        # add a second one at 0.
        self.assertEqual([(c[0], c[2], c[3]) for c in comps],
                         [(0, "vptr", "vfptr"), (4, "field", "a"), (8, "field", "b")])
        self.assertEqual(notes, [])

    def test_external_base_single_component(self):
        model = {"CIncludeView": _rec(bases=["CView"], fields=[("m", "int", 0)])}
        layouts = {"CIncludeView": {"size": 68, "bases": {"CView": 0},
                                    "fields": {"m": {"offset": 64, "size": 4}}}}
        _s, comps, _n = plan_components("CIncludeView", model, layouts, {"CView": 64})
        self.assertEqual(comps[0], (0, 64, "base_ext", "base_CView", "CView"))
        self.assertEqual(comps[1][3], "m")

    def test_unknown_base_noted_not_invented(self):
        model = {"X": _rec(bases=["Mystery"], fields=[])}
        layouts = {"X": {"size": 8, "bases": {"Mystery": 0}, "fields": {}}}
        _s, comps, notes = plan_components("X", model, layouts, {})
        self.assertEqual(comps, [])
        self.assertIn("unknown_base:Mystery", notes)

    def test_overlap_is_pruned_and_noted(self):
        model = {"X": _rec(fields=[("a", "int", 0), ("b", "int", 0)])}
        layouts = {"X": {"size": 8, "bases": {}, "fields": {
            "a": {"offset": 0, "size": 4}, "b": {"offset": 2, "size": 4}}}}
        _s, comps, notes = plan_components("X", model, layouts, {})
        self.assertEqual([c[3] for c in comps], ["a"])
        self.assertTrue(any(n.startswith("overlap:b") for n in notes))

    def test_exceeds_size_noted(self):
        model = {"X": _rec(fields=[("a", "int", 0)])}
        layouts = {"X": {"size": 4, "bases": {}, "fields": {"a": {"offset": 2, "size": 4}}}}
        _s, _c, notes = plan_components("X", model, layouts, {})
        self.assertTrue(any(n.startswith("exceeds_size") for n in notes))

    def test_oracle_skipped_field_left_undefined(self):
        # A bitfield the oracle could not measure has no layout entry -> no component.
        model = {"X": _rec(fields=[("bits", "unsigned int", 0)])}
        layouts = {"X": {"size": 4, "bases": {}, "fields": {}}}
        _s, comps, notes = plan_components("X", model, layouts, {})
        self.assertEqual(comps, [])
        self.assertEqual(notes, [])


if __name__ == "__main__":
    unittest.main()
