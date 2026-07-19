"""Tests for the Clang-AST declaration index walker (no clang invocation).

The AST-walk / kind-classification logic is exercised against synthetic AST node
dicts shaped like clang's `-ast-dump=json` output, so the qualified-name scoping
and the static/instance/namespace/ctor/dtor classification are pinned without a
real parse.
"""

import unittest

from tools.clang_ast_index import DeclInfo, _walk


def _method(name, storage=None, params=(), ret="void", kind="CXXMethodDecl"):
    node = {"kind": kind, "name": name,
            "type": {"qualType": f"{ret} ({', '.join(params)})" if params else f"{ret} ()"},
            "inner": [{"kind": "ParmVarDecl", "type": {"qualType": p}} for p in params]}
    if storage:
        node["storageClass"] = storage
    return node


def _record(name, *members):
    return {"kind": "CXXRecordDecl", "name": name, "inner": list(members)}


def _namespace(name, *members):
    return {"kind": "NamespaceDecl", "name": name, "inner": list(members)}


def _tu(*decls):
    return {"kind": "TranslationUnitDecl", "inner": list(decls)}


def _index(tu):
    idx = {}
    _walk(tu, [], idx)
    return idx


class WalkTest(unittest.TestCase):
    def test_instance_method(self):
        idx = _index(_tu(_record("TCity", _method("Grow", params=("int",)))))
        self.assertEqual(idx["TCity::Grow"], [DeclInfo("instance_method", False, "void", ("int",), True)])

    def test_static_method(self):
        idx = _index(_tu(_record("TMapMgr", _method("Compute", storage="static", params=("short",), ret="int"))))
        info = idx["TMapMgr::Compute"][0]
        self.assertEqual(info.kind, "static_method")
        self.assertTrue(info.is_static)
        self.assertFalse(info.has_this)
        self.assertEqual(info.ret, "int")
        self.assertEqual(info.params, ("short",))

    def test_constructor_and_destructor(self):
        idx = _index(_tu(_record(
            "TArmyMission",
            _method("TArmyMission", params=("int",), kind="CXXConstructorDecl"),
            _method("~TArmyMission", kind="CXXDestructorDecl"))))
        self.assertEqual(idx["TArmyMission::TArmyMission"][0].kind, "constructor")
        self.assertTrue(idx["TArmyMission::TArmyMission"][0].has_this)
        self.assertEqual(idx["TArmyMission::~TArmyMission"][0].kind, "destructor")

    def test_free_function_vs_namespace_function(self):
        idx = _index(_tu(
            _method("GlobalHelper", params=("int",), kind="FunctionDecl"),
            _namespace("Ns", _method("Helper", params=("int",), kind="FunctionDecl"))))
        self.assertEqual(idx["GlobalHelper"][0].kind, "free_function")
        self.assertEqual(idx["Ns::Helper"][0].kind, "namespace_function")

    def test_static_free_function(self):
        idx = _index(_tu(_method("FileLocal", storage="static", kind="FunctionDecl")))
        self.assertEqual(idx["FileLocal"][0].kind, "static_method")

    def test_overloads_collected_as_list(self):
        idx = _index(_tu(_record(
            "TView",
            _method("Add", params=("int",)),
            _method("Add", params=("int", "int")))))
        kinds = idx["TView::Add"]
        self.assertEqual(len(kinds), 2)
        self.assertEqual({len(d.params) for d in kinds}, {1, 2})


class ResolveEntityKindTest(unittest.TestCase):
    def setUp(self):
        from tools.ghidra.apply_source_signatures import resolve_entity_kind
        self.resolve = resolve_entity_kind
        self.index = {
            "TMapMgr::Compute": [DeclInfo("static_method", True, "int", ("short",), False)],
            "TView::Add": [DeclInfo("instance_method", False, "void", ("int",), True),
                           DeclInfo("instance_method", False, "void", ("int", "int"), True)],
            "Mixed::Fn": [DeclInfo("static_method", True, "int", ("int",), False),
                          DeclInfo("instance_method", False, "int", ("int", "int"), True)],
        }

    def test_uses_index_kind(self):
        self.assertEqual(self.resolve(self.index, "TMapMgr::Compute", 1, "instance_method"),
                         "static_method")

    def test_falls_back_when_absent(self):
        self.assertEqual(self.resolve(self.index, "Unknown::Name", 0, "free_function"),
                         "free_function")

    def test_disambiguates_overload_by_arity(self):
        # Both TView::Add are instance_method, so either arity resolves the same.
        self.assertEqual(self.resolve(self.index, "TView::Add", 2, "free_function"),
                         "instance_method")

    def test_ambiguous_overload_arity_picks_matching(self):
        self.assertEqual(self.resolve(self.index, "Mixed::Fn", 2, "free_function"),
                         "instance_method")
        self.assertEqual(self.resolve(self.index, "Mixed::Fn", 1, "free_function"),
                         "static_method")

    def test_ambiguous_no_arity_match_falls_back(self):
        # arity 5 matches neither overload and the kinds disagree -> fallback.
        self.assertEqual(self.resolve(self.index, "Mixed::Fn", 5, "free_function"),
                         "free_function")

    def test_no_index_returns_fallback(self):
        self.assertEqual(self.resolve(None, "TMapMgr::Compute", 1, "instance_method"),
                         "instance_method")


if __name__ == "__main__":
    unittest.main()
