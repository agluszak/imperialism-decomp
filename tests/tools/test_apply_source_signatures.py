"""Unit tests for the source-model signature projector's parse layer.

Only the pure-Python prototype parsing is covered here (no Ghidra): the
type/name disambiguation and MSVC-qualifier stripping are where the real bugs
lived, and they must keep MFC reviewed prototypes and game-source declarations
parsing to the same clean (cc, return, [param types]) shape.
"""

import unittest

from tools.ghidra.apply_source_signatures import (
    _is_placeholder_return,
    _param_type_only,
    parse_prototype,
)


class ParsePrototypeTest(unittest.TestCase):
    def test_thiscall_method_return_and_params(self):
        cc, ret, params, is_method = parse_prototype(
            "void TWindow::HandleEvent(int commandId, TEventHandler* h, TEvent* e)")
        self.assertIsNone(cc)  # convention implied by the caller (method => thiscall)
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["int", "TEventHandler*", "TEvent*"])
        self.assertTrue(is_method)

    def test_return_type_excludes_class_qualifier(self):
        # The historical bug: ret came out as "void ImperialismCommandLineInfo::".
        cc, ret, params, is_method = parse_prototype(
            "void ImperialismCommandLineInfo::ParseParam(LPCSTR p, BOOL f, BOOL last)")
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["LPCSTR", "BOOL", "BOOL"])

    def test_ctor_has_void_return(self):
        cc, ret, params, is_method = parse_prototype(
            "TArmyMission::TArmyMission(int nodeKey)")
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["int"])

    def test_free_function_stdcall(self):
        cc, ret, params, is_method = parse_prototype(
            "unsigned short __stdcall Foo(short a, int b)")
        self.assertEqual(cc, "__stdcall")
        self.assertEqual(ret, "unsigned short")
        self.assertEqual(params, ["short", "int"])
        self.assertFalse(is_method)

    def test_void_param_list_is_empty(self):
        _cc, _ret, params, _m = parse_prototype("void TView::Draw(void)")
        self.assertEqual(params, [])
        _cc, _ret, params2, _m = parse_prototype("void TView::Tick()")
        self.assertEqual(params2, [])

    def test_mfc_prototype_strips_access_and_virtual(self):
        cc, ret, params, is_method = parse_prototype(
            "public: virtual void __thiscall CDocTemplate::InitialUpdateFrame("
            "class CFrameWnd *, class CDocument *, int)")
        self.assertEqual(cc, "__thiscall")
        self.assertEqual(ret, "void")
        self.assertEqual(params, ["class CFrameWnd *", "class CDocument *", "int"])

    def test_mfc_typeonly_params_keep_full_type(self):
        # No parameter names: the trailing word completes the type, not a name.
        _cc, _ret, params, _m = parse_prototype(
            "public: int __thiscall CScrollView::DoMouseWheel("
            "unsigned int, short, class CPoint)")
        self.assertEqual(params, ["unsigned int", "short", "class CPoint"])

    def test_placeholder_undefined_return(self):
        _cc, ret, params, _m = parse_prototype(
            "undefined TMapDialog::RenderStrategicMapTileCell(short, short, short)")
        self.assertEqual(ret, "undefined")
        self.assertTrue(_is_placeholder_return(ret))
        self.assertEqual(params, ["short", "short", "short"])

    def test_unparsable_returns_none(self):
        self.assertIsNone(parse_prototype("not a prototype at all"))


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
