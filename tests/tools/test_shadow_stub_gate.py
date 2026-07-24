"""Unit tests for the shadow-stub gate's degenerate-body classifier.

The gate's value is precision: it must flag a non-virtual do-nothing method on a
vtable class (the TMapMgr/TAmtBar family) while never flagging a real body or a
properly-claimed one. These tests pin the body classifier, which is the part with
the subtle tree-sitter logic.
"""

import unittest

import tree_sitter_cpp
from tree_sitter import Language, Parser

from tools.workflow.check_shadow_stubs import is_degenerate_body

_CPP = Language(tree_sitter_cpp.language())


def _body(src: str):
    tree = Parser(_CPP).parse(src.encode())
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "function_definition":
            b = node.child_by_field_name("body")
            if b is not None and b.type == "compound_statement":
                return b
    raise AssertionError("no function body parsed")


class DegenerateBodyTests(unittest.TestCase):
    def test_empty_body_is_degenerate(self):
        self.assertTrue(is_degenerate_body(_body("void C::f() {}")))

    def test_void_casts_only_is_degenerate(self):
        self.assertTrue(is_degenerate_body(_body("void C::f(int a, int b){ (void)a; (void)b; }")))

    def test_constant_return_is_degenerate(self):
        self.assertTrue(is_degenerate_body(_body("int C::f(){ return 0; }")))
        self.assertTrue(is_degenerate_body(_body("bool C::f(){ (void)0; return false; }")))

    def test_real_body_is_not_degenerate(self):
        self.assertFalse(is_degenerate_body(_body("int C::f(){ return g(); }")))
        self.assertFalse(
            is_degenerate_body(_body("void C::f(int a){ (void)a; this->x = 1; }"))
        )

    def test_return_of_member_is_not_degenerate(self):
        self.assertFalse(is_degenerate_body(_body("int C::f(){ return this->value; }")))


if __name__ == "__main__":
    unittest.main()
