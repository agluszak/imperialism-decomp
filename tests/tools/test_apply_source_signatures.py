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
    _flattened_by_value_storage_matches,
    _is_placeholder_return,
    _parameterless_overdeclaration_is_proven,
    _param_type_only,
    _queue_out_for_mode,
    classify_convergence,
    default_convention,
    parse_prototype,
    select_named_datatype,
)


def _exp(cc="__cdecl", n_params=0, has_this=False, param_sizes=(), has_varargs=False,
        ret_size=None):
    return {
        "cc": cc, "n_params": n_params, "has_this": has_this,
        "param_sizes": list(param_sizes), "has_varargs": has_varargs, "ret_size": ret_size,
    }


def _db(cc="__cdecl", n_params=0, has_this=False, param_sizes=(), has_varargs=False,
        has_sret=False, custom_storage=False, ret_size=None):
    return {
        "cc": cc, "n_params": n_params, "has_this": has_this,
        "param_sizes": list(param_sizes), "has_varargs": has_varargs,
        "has_sret": has_sret, "custom_storage": custom_storage, "ret_size": ret_size,
    }


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

    def test_callback_macro_normalizes_to_stdcall_and_strips_from_return(self):
        # Regression: a real Win32 timer-proc declaration
        # (include/game/TMouseCaptureState.h) leaked "VOID CALLBACK" into the
        # return-type text as an unresolvable weak type, because nothing
        # recognized CALLBACK as a __stdcall synonym.
        cc, ret, params, kind = parse_prototype(
            "VOID CALLBACK NotifyThing(HWND hwnd, UINT message, UINT timerId, DWORD dwTime)")
        self.assertEqual(cc, "__stdcall")
        self.assertEqual(ret, "VOID")
        self.assertEqual(kind, "free_function")

    def test_callback_macro_lowercase_void(self):
        cc, ret, _params, _kind = parse_prototype(
            "void CALLBACK DispatchThing(HWND hwnd, UINT msg)")
        self.assertEqual(cc, "__stdcall")
        self.assertEqual(ret, "void")

    def test_winapi_apientry_pascal_all_normalize_to_stdcall(self):
        for macro in ("WINAPI", "APIENTRY", "PASCAL"):
            cc, _ret, _params, _kind = parse_prototype(f"void {macro} Foo(int a)")
            self.assertEqual(cc, "__stdcall", macro)

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

    def test_dunder_inline_stripped_from_return_type(self):
        # Regression: real declaration (include/game/TOcean.h) -- `\binline\b`
        # doesn't match inside "__inline" (no word boundary before "inline"
        # when it's preceded by underscores, themselves word characters), so
        # the qualifier leaked into the return type as "__inline TZone*".
        _cc, ret, params, kind = parse_prototype(
            "__inline TZone* GetMapActionContextEntryByNationCodeOffset17(short nationCode)")
        self.assertEqual(ret, "TZone*")
        self.assertEqual(params, ["short"])
        self.assertEqual(kind, "free_function")

    def test_qualified_enum_param_with_no_name_keeps_whole_type(self):
        # Regression: a real MFC prototype (CDocTemplate::GetDocString) has a
        # nameless `enum CDocTemplate::DocStringIndex` parameter. The old
        # trailing-identifier regex only captured the last segment
        # ("DocStringIndex"), mistaking it for a parameter name and truncating
        # the type to the bogus, empty-after-cleanup "enum CDocTemplate::".
        _cc, _ret, params, _k = parse_prototype(
            "public: virtual int __thiscall CDocTemplate::GetDocString("
            "class CString &, enum CDocTemplate::DocStringIndex) const")
        self.assertEqual(params, ["class CString &", "enum CDocTemplate::DocStringIndex"])


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


class QualityRankTest(unittest.TestCase):
    def test_rank_covers_every_grade_resolve_quality_emits(self):
        from tools.ghidra.apply_source_signatures import _QUALITY_RANK
        # Every grade resolve_quality can return must be rankable, or the structural
        # audit KeyErrors. Keep this list in sync with resolve_quality's returns.
        for grade in ("exact_complete", "canonical_alias", "opaque_pointee",
                      "generic_pointer_fallback", "ambiguous_simple_name",
                      "opaque_by_value", "unresolved"):
            self.assertIn(grade, _QUALITY_RANK, grade)

    def test_opaque_by_value_ranks_worse_than_pointer_grades(self):
        from tools.ghidra.apply_source_signatures import _QUALITY_RANK
        self.assertGreater(_QUALITY_RANK["opaque_by_value"], _QUALITY_RANK["opaque_pointee"])
        self.assertGreater(_QUALITY_RANK["opaque_by_value"], _QUALITY_RANK["exact_complete"])


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

    def test_array_param_decays_to_pointer(self):
        self.assertEqual(_param_type_only("int arr[4]"), "int*")

    def test_postfix_const_pointer_array_param_decays(self):
        # real bug: TMapMgr::SeedRecruitSearchVisitedStateFromMilitaryUnitCandidates
        self.assertEqual(
            _param_type_only("class TMilitaryUnit* const candidates[6]"),
            "class TMilitaryUnit* const*",
        )

    def test_postfix_const_pointer_without_array_keeps_name_dropped(self):
        self.assertEqual(
            _param_type_only("class TMilitaryUnit* const candidate"),
            "class TMilitaryUnit* const",
        )

    def test_prefix_const_still_needs_completion_word(self):
        self.assertEqual(_param_type_only("class CPoint"), "class CPoint")


class PlaceholderReturnTest(unittest.TestCase):
    def test_placeholders(self):
        for t in ("undefined", "undefined1", "undefined4", "undefined8"):
            self.assertTrue(_is_placeholder_return(t), t)

    def test_real_types_are_not_placeholders(self):
        for t in ("void", "int", "CPoint", "unsigned short"):
            self.assertFalse(_is_placeholder_return(t), t)


class FlattenedByValueStorageTest(unittest.TestCase):
    def test_cpoint_after_two_pointer_sized_params(self):
        self.assertTrue(_flattened_by_value_storage_matches(
            [4, 4, 8], [4, 4, 4, 4]))

    def test_cpoint_after_scalar_param(self):
        self.assertTrue(_flattened_by_value_storage_matches([4, 8], [4, 4, 4]))

    def test_requires_wide_source_parameter(self):
        self.assertFalse(_flattened_by_value_storage_matches([4, 4], [4, 4]))

    def test_rejects_different_stack_storage(self):
        self.assertFalse(_flattened_by_value_storage_matches([4, 8], [4, 4]))

    def test_rejects_unknown_sizes(self):
        self.assertFalse(_flattened_by_value_storage_matches([4, None], [4, 4]))


class ParameterlessOverdeclarationTest(unittest.TestCase):
    def test_thiscall_plain_ret_proves_zero_explicit_parameters(self):
        self.assertTrue(_parameterless_overdeclaration_is_proven(
            "__thiscall", 0, True, "__thiscall", 1, True, 0))

    def test_stdcall_plain_ret_proves_zero_explicit_parameters(self):
        self.assertTrue(_parameterless_overdeclaration_is_proven(
            "__stdcall", 0, False, "__stdcall", 2, False, 0))

    def test_cdecl_cleanup_cannot_prove_parameter_count(self):
        self.assertFalse(_parameterless_overdeclaration_is_proven(
            "__cdecl", 0, False, "__cdecl", 1, False, 0))

    def test_nonzero_cleanup_rejects_parameterless_source(self):
        self.assertFalse(_parameterless_overdeclaration_is_proven(
            "__thiscall", 0, True, "__thiscall", 1, True, 4))

    def test_receiver_mismatch_is_not_safe(self):
        self.assertFalse(_parameterless_overdeclaration_is_proven(
            "__thiscall", 0, True, "__thiscall", 1, False, 0))


class ClassifyConvergenceTest(unittest.TestCase):
    """The three-tier structural convergence classifier (Task 4): logical (cc/this/
    arity/varargs) -> abi_storage (param+return sizes, sret) -> semantic (real type
    identity, not just pointer-sized ABI compatibility). Each tier only evaluates
    once every earlier tier converged."""

    def test_fully_semantically_converged(self):
        exp = _exp(cc="__thiscall", n_params=1, has_this=True, param_sizes=[4], ret_size=4)
        db = _db(cc="__thiscall", n_params=1, has_this=True, param_sizes=[4], ret_size=4)
        result = classify_convergence(exp, db, "exact_complete", "exact_complete")
        self.assertEqual(result["logical"], "logical_converged")
        self.assertEqual(result["abi"], "abi_storage_converged")
        self.assertEqual(result["semantic"], "semantically_converged")

    def test_db_cc_unknown_is_distinct_from_incomplete(self):
        # CC never resolved at all -- distinct bucket from "CC known, arity short".
        exp = _exp(n_params=2)
        db = _db(cc="unknown", n_params=0)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "db_cc_unknown")
        self.assertIsNone(result["abi"])
        self.assertIsNone(result["semantic"])

    def test_known_cc_short_arity_is_signature_incomplete(self):
        # CC IS known, but DB shows 0 explicit params where source expects some --
        # a genuinely different situation from cc_unknown (Ghidra has a plausible
        # convention already; it's just missing the parameter list).
        exp = _exp(cc="__cdecl", n_params=2)
        db = _db(cc="__cdecl", n_params=0)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "db_signature_incomplete")

    def test_known_cc_zero_params_both_sides_is_not_incomplete(self):
        # The "known-CC/zero-parameter" case Task 4 calls out: both sides genuinely
        # agree on zero explicit params -- must NOT be misclassified as incomplete.
        exp = _exp(cc="__cdecl", n_params=0)
        db = _db(cc="__cdecl", n_params=0)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "logical_converged")

    def test_convention_mismatch(self):
        exp = _exp(cc="__thiscall", has_this=True)
        db = _db(cc="__cdecl", has_this=False)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "convention_mismatch")

    def test_this_presence_mismatch(self):
        exp = _exp(cc="__cdecl", has_this=True)
        db = _db(cc="__cdecl", has_this=False)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "this_presence_mismatch")

    def test_param_count_mismatch(self):
        exp = _exp(cc="__cdecl", n_params=2)
        db = _db(cc="__cdecl", n_params=1)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "param_count_mismatch")

    def test_varargs_mismatch(self):
        exp = _exp(cc="__cdecl", has_varargs=True)
        db = _db(cc="__cdecl", has_varargs=False)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "varargs_mismatch")

    def test_abi_param_size_mismatch_blocks_semantic_tier(self):
        exp = _exp(cc="__cdecl", n_params=1, param_sizes=[4])
        db = _db(cc="__cdecl", n_params=1, param_sizes=[2])
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["logical"], "logical_converged")
        self.assertTrue(result["abi"].startswith("abi_storage_mismatch:"))
        self.assertIn("param0:exp=4,db=2", result["abi"])
        self.assertIsNone(result["semantic"])

    def test_abi_return_size_mismatch(self):
        exp = _exp(cc="__cdecl", ret_size=8)
        db = _db(cc="__cdecl", ret_size=4)
        result = classify_convergence(exp, db, "exact_complete", "exact_complete")
        self.assertTrue(result["abi"].startswith("abi_storage_mismatch:"))
        self.assertIn("return:exp=8,db=4", result["abi"])

    def test_sret_expected_but_db_has_none(self):
        # A by-value return > 4 bytes should have an sret auto-param in the DB.
        exp = _exp(cc="__cdecl", ret_size=12)
        db = _db(cc="__cdecl", ret_size=12, has_sret=False)
        result = classify_convergence(exp, db, "exact_complete", "exact_complete")
        self.assertTrue(result["abi"].startswith("abi_storage_mismatch:"))
        self.assertIn("sret_mismatch:exp=True,db=False", result["abi"])

    def test_sret_expected_and_present_converges(self):
        exp = _exp(cc="__cdecl", ret_size=12)
        db = _db(cc="__cdecl", ret_size=12, has_sret=True)
        result = classify_convergence(exp, db, "exact_complete", "exact_complete")
        self.assertEqual(result["abi"], "abi_storage_converged")

    def test_placeholder_return_skips_abi_return_check(self):
        # ret_size=None means "not authoritative" (a placeholder return or an
        # unresolved source type) -- must not falsely fail the ABI tier.
        exp = _exp(cc="__cdecl", ret_size=None)
        db = _db(cc="__cdecl", ret_size=4, has_sret=False)
        result = classify_convergence(exp, db, "exact_complete", None)
        self.assertEqual(result["abi"], "abi_storage_converged")

    def test_weak_param_type_blocks_semantic_tier_only(self):
        # ABI-compatible (both 4 bytes) but the param's resolved type is only a
        # generic void* stand-in, not a real semantic match.
        exp = _exp(cc="__cdecl", n_params=1, param_sizes=[4])
        db = _db(cc="__cdecl", n_params=1, param_sizes=[4])
        result = classify_convergence(exp, db, "generic_pointer_fallback", None)
        self.assertEqual(result["logical"], "logical_converged")
        self.assertEqual(result["abi"], "abi_storage_converged")
        self.assertEqual(result["semantic"], "weak_type_resolution:generic_pointer_fallback")

    def test_weak_return_type_also_blocks_semantic_tier(self):
        exp = _exp(cc="__cdecl", ret_size=4)
        db = _db(cc="__cdecl", ret_size=4)
        result = classify_convergence(exp, db, "exact_complete", "opaque_pointee")
        self.assertEqual(result["semantic"], "weak_type_resolution:opaque_pointee")

    def test_canonical_alias_counts_as_semantic(self):
        # canonical_alias (a known MFC/Win32 typedef) is semantic, not just ABI.
        exp = _exp(cc="__cdecl", n_params=1, param_sizes=[4])
        db = _db(cc="__cdecl", n_params=1, param_sizes=[4])
        result = classify_convergence(exp, db, "canonical_alias", None)
        self.assertEqual(result["semantic"], "semantically_converged")


class QueueOutForModeTest(unittest.TestCase):
    """Each projector mode gets its own default queue file -- the fix for the
    silent last-writer-wins collision (all three used to share one filename with
    no --queue-out override in any `just` recipe)."""

    class _Args:
        def __init__(self, queue_out=None):
            self.queue_out = queue_out

    def test_default_paths_are_distinct_per_mode(self):
        paths = {mode: _queue_out_for_mode(self._Args(), mode)
                 for mode in ("in_stack", "divergent", "packed")}
        self.assertEqual(len(set(paths.values())), 3, paths)

    def test_explicit_override_wins_for_every_mode(self):
        args = self._Args(queue_out="/tmp/shared_queue.csv")
        for mode in ("in_stack", "divergent", "packed"):
            self.assertEqual(_queue_out_for_mode(args, mode), "/tmp/shared_queue.csv")


class SelectNamedDatatypeTest(unittest.TestCase):
    """The simple-name ambiguity resolver (Task 3): excludes two disposable-
    placeholder categories (bare FunctionDefinitions, /Demangler stubs) from the
    ambiguity count before flagging a real collision. Regression coverage for the
    live bug found applying CDataExchange/CView: a pre-existing empty
    `/Demangler/CView` stub had been silently "winning" the lookup (count=1) until
    a real `/CView` was added, at which point naive counting would have flagged
    `ambiguous_simple_name` for a real-definition-vs-disposable-stub pair."""

    def test_single_candidate_is_unambiguous(self):
        idx, count = select_named_datatype([(False, "/")])
        self.assertEqual((idx, count), (0, 1))

    def test_demangler_stub_excluded_when_real_definition_exists(self):
        # order matches the live case: root struct added after the stub existed
        candidates = [(False, "/Demangler"), (False, "/")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(idx, 1)  # picks the real (non-stub) one
        self.assertEqual(count, 1)  # not ambiguous

    def test_demangler_stub_excluded_regardless_of_order(self):
        candidates = [(False, "/"), (False, "/Demangler")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(idx, 0)
        self.assertEqual(count, 1)

    def test_two_real_definitions_are_genuinely_ambiguous(self):
        candidates = [(False, "/"), (False, "/MFC/library")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(count, 2)  # a real ambiguity, not excluded

    def test_bare_function_definition_excluded_when_real_type_exists(self):
        # e.g. WNDPROC typedef (real) vs .../functions/WNDPROC (bare FunctionDefinition)
        candidates = [(True, "/functions"), (False, "/")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(idx, 1)
        self.assertEqual(count, 1)

    def test_every_candidate_a_function_definition_falls_back_to_all(self):
        candidates = [(True, "/functions"), (True, "/functions")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(count, 2)

    def test_every_candidate_a_demangler_stub_falls_back_to_all(self):
        candidates = [(False, "/Demangler"), (False, "/Demangler")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(count, 2)

    def test_both_exclusions_combined(self):
        # bare FunctionDefinition, Demangler stub, and one real definition
        candidates = [(True, "/functions"), (False, "/Demangler"), (False, "/")]
        idx, count = select_named_datatype(candidates)
        self.assertEqual(idx, 2)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
