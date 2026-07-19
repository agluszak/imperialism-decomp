"""Unit tests for the source-model signature projector's pure-Python layer.

No Ghidra: covers prototype parsing (type/name disambiguation, MSVC-qualifier
stripping), the entity-kind classification that picks the calling convention,
and the before/after in_stack bucket decision. The parse layer and the
convergence classifier are where the real bugs have lived, so they are pinned
here; the transactional apply path has a separate live-Ghidra smoke test.
"""

import unittest

from tools.ghidra.apply_source_signatures import (
    _classify_projection,
    _is_placeholder_return,
    _param_type_only,
    default_convention,
    parse_prototype,
)


class ParsePrototypeTest(unittest.TestCase):
    def test_instance_method_return_and_params(self):
        cc, ret, params, kind = parse_prototype(
            "void TWindow::HandleEvent(int commandId, TEventHandler* h, TEvent* e)")
        self.assertIsNone(cc)  # convention implied (instance method => thiscall)
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["int", "TEventHandler*", "TEvent*"])
        self.assertEqual(kind, "instance_method")

    def test_return_type_excludes_class_qualifier(self):
        # The historical bug: ret came out as "void ImperialismCommandLineInfo::".
        _cc, ret, params, _k = parse_prototype(
            "void ImperialismCommandLineInfo::ParseParam(LPCSTR p, BOOL f, BOOL last)")
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["LPCSTR", "BOOL", "BOOL"])

    def test_ctor_kind_and_void_return(self):
        _cc, ret, params, kind = parse_prototype("TArmyMission::TArmyMission(int nodeKey)")
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["int"])
        self.assertEqual(kind, "constructor")

    def test_dtor_kind(self):
        _cc, _ret, _params, kind = parse_prototype("TArmyMission::~TArmyMission(void)")
        self.assertEqual(kind, "destructor")

    def test_free_function_stdcall(self):
        cc, ret, params, kind = parse_prototype(
            "unsigned short __stdcall Foo(short a, int b)")
        self.assertEqual(cc, "__stdcall")
        self.assertEqual(ret, "unsigned short")
        self.assertEqual(params, ["short", "int"])
        self.assertEqual(kind, "free_function")

    def test_void_param_list_is_empty(self):
        _cc, _ret, params, _k = parse_prototype("void TView::Draw(void)")
        self.assertEqual(params, [])
        _cc, _ret, params2, _k = parse_prototype("void TView::Tick()")
        self.assertEqual(params2, [])

    def test_mfc_prototype_strips_access_and_virtual(self):
        cc, ret, params, kind = parse_prototype(
            "public: virtual void __thiscall CDocTemplate::InitialUpdateFrame("
            "class CFrameWnd *, class CDocument *, int)")
        self.assertEqual(cc, "__thiscall")
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["class CFrameWnd *", "class CDocument *", "int"])
        self.assertEqual(kind, "instance_method")

    def test_mfc_typeonly_params_keep_full_type(self):
        _cc, _ret, params, _k = parse_prototype(
            "public: int __thiscall CScrollView::DoMouseWheel("
            "unsigned int, short, class CPoint)")
        self.assertEqual(params, ["unsigned int", "short", "class CPoint"])

    def test_placeholder_undefined_return(self):
        _cc, ret, params, _k = parse_prototype(
            "undefined TMapDialog::RenderStrategicMapTileCell(short, short, short)")
        self.assertEqual(ret, "undefined")
        self.assertTrue(_is_placeholder_return(ret))
        self.assertEqual(params, ["short", "short", "short"])

    def test_unparsable_returns_none(self):
        self.assertIsNone(parse_prototype("not a prototype at all"))

    def test_ctor_with_member_init_list_ignores_init_list(self):
        # Regression: the LAST-paren-group parse grabbed the init list, yielding
        # junk args like ") : TView(". Use the first balanced group.
        _cc, ret, params, kind = parse_prototype("TMapPreviewView::TMapPreviewView() : TView()")
        self.assertEqual(ret, "void")
        self.assertEqual(params, [])
        self.assertEqual(kind, "constructor")

    def test_ctor_with_args_and_init_list(self):
        _cc, _ret, params, kind = parse_prototype(
            "TPictureButton::TPictureButton(TView* parent, int id) : TPicture(parent), field60(0)")
        self.assertEqual(params, ["TView*", "int"])
        self.assertEqual(kind, "constructor")

    def test_function_pointer_param_kept_balanced(self):
        _cc, _ret, params, _k = parse_prototype("TFoo::TFoo(int (*cb)(int), TView* v) : TBase()")
        self.assertEqual(params, ["int (*cb)(int)", "TView*"])


class EntityKindClassificationTest(unittest.TestCase):
    """Static/namespace classification — the convention-selection surface.

    An explicit `static` IS honoured (=> static_method => __cdecl). The known
    limitation is that an out-of-class definition head does not repeat `static`,
    and `Ns::fn` is indistinguishable from `Class::method`, so both collapse to
    `instance_method` until a compiler-backed declaration index exists.
    """

    def test_explicit_static_member_is_cdecl(self):
        # e.g. a reviewed identity that carries the keyword.
        _cc, _ret, _params, kind = parse_prototype(
            "public: static int __cdecl CWnd::GetSomething(int)")
        self.assertEqual(kind, "static_method")
        self.assertEqual(default_convention(kind), "__cdecl")

    def test_static_free_function(self):
        _cc, _ret, _params, kind = parse_prototype("static int _chsize_lk(int fh, long size)")
        self.assertEqual(kind, "static_method")
        self.assertEqual(default_convention(kind), "__cdecl")

    def test_instance_method_default_thiscall(self):
        _cc, _ret, _params, kind = parse_prototype("void TCity::Grow(int amount)")
        self.assertEqual(kind, "instance_method")
        self.assertEqual(default_convention(kind), "__thiscall")

    def test_ctor_dtor_are_thiscall(self):
        self.assertEqual(default_convention("constructor"), "__thiscall")
        self.assertEqual(default_convention("destructor"), "__thiscall")

    def test_free_function_default_cdecl(self):
        _cc, _ret, _params, kind = parse_prototype("void GlobalHelper(int a)")
        self.assertEqual(kind, "free_function")
        self.assertEqual(default_convention(kind), "__cdecl")

    def test_KNOWN_LIMITATION_namespace_fn_looks_like_method(self):
        # Documents the #95 gap: a namespace-qualified free function without an
        # explicit static/convention is (incorrectly) classified instance_method.
        _cc, _ret, _params, kind = parse_prototype("void Ns::DoThing(int a)")
        self.assertEqual(kind, "instance_method")  # not free_function — the gap


class ClassifyProjectionTest(unittest.TestCase):
    """before/after in_stack -> (commit, reason). None after == verify failed."""

    def test_fully_converged_commits_no_reason(self):
        commit, reason = _classify_projection({0xc}, set())
        self.assertTrue(commit)
        self.assertIsNone(reason)

    def test_residual_commits_with_reason(self):
        commit, reason = _classify_projection({0xc}, {0x9, 0xd})
        self.assertTrue(commit)
        self.assertTrue(reason.startswith("params_bound_residual:"))
        self.assertIn("0x9", reason)
        self.assertIn("0xd", reason)

    def test_flagged_offset_unbound_rejects(self):
        commit, reason = _classify_projection({0x6}, {0x6})
        self.assertFalse(commit)
        self.assertTrue(reason.startswith("dynamic_storage_insufficient:"))
        self.assertIn("0x6", reason)

    def test_partial_overlap_rejects(self):
        # One original offset still present -> reject even if another cleared.
        commit, reason = _classify_projection({0x6, 0xa}, {0x6})
        self.assertFalse(commit)
        self.assertTrue(reason.startswith("dynamic_storage_insufficient:"))
        self.assertIn("0x6", reason)
        self.assertNotIn("0xa", reason)  # only the still-unbound offset is reported

    def test_decompile_failed_after_rejects(self):
        commit, reason = _classify_projection({0x6}, None)
        self.assertFalse(commit)
        self.assertEqual(reason, "decompile_failed:after")


class ParamTypeOnlyTest(unittest.TestCase):
    def test_named_scalar_drops_name(self):
        self.assertEqual(_param_type_only("short nPictureId"), "short")
        self.assertEqual(_param_type_only("int requestedCount"), "int")

    def test_named_pointer_drops_name(self):
        self.assertEqual(_param_type_only("TEventHandler* handler"), "TEventHandler*")
        self.assertEqual(_param_type_only("void* item"), "void*")

    def test_typeonly_keeps_completion_word(self):
        self.assertEqual(_param_type_only("class CPoint"), "class CPoint")
        self.assertEqual(_param_type_only("struct tagPOINT"), "struct tagPOINT")
        self.assertEqual(_param_type_only("unsigned int"), "unsigned int")
        self.assertEqual(_param_type_only("unsigned long tag"), "unsigned long")

    def test_pointer_tail_is_whole_type(self):
        self.assertEqual(_param_type_only("class CWnd *"), "class CWnd *")

    def test_bare_keyword(self):
        self.assertEqual(_param_type_only("int"), "int")


class PlaceholderReturnTest(unittest.TestCase):
    def test_placeholders(self):
        for t in ("undefined", "undefined1", "undefined4", "undefined8"):
            self.assertTrue(_is_placeholder_return(t), t)

    def test_real_types_are_not_placeholders(self):
        for t in ("void", "int", "CPoint", "unsigned short"):
            self.assertFalse(_is_placeholder_return(t), t)


if __name__ == "__main__":
    unittest.main()
