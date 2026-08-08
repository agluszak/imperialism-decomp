"""Tests for the CString source-model and call-safety gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.workflow.check_cstring_usage import collect_findings, split_call_arguments


def _findings(text: str) -> set[tuple[str, str]]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source_dir = root / "src" / "game"
        source_dir.mkdir(parents=True)
        (source_dir / "Fake.cpp").write_text(text, encoding="utf-8")
        found = collect_findings([str(source_dir)], root)
    return {(finding.kind, finding.detail) for finding in found}


class TestCStringInternalModel(unittest.TestCase):
    def test_pseudo_and_atl_models_fail(self):
        for source in (
            "struct GhStr { char* value; };",
            "#include <atlstr.h>",
            "CStringT<char, Traits> value;",
            "CAtlString value;",
        ):
            self.assertTrue(_findings(source), source)

    def test_internal_member_access_fails(self):
        self.assertTrue(_findings("const char* p = value.m_pchData;"))
        self.assertTrue(_findings("CStringData* data = GetData(); data->nRefs++;"))

    def test_comments_do_not_trigger(self):
        self.assertEqual(_findings("// GhStr and CStringData are forbidden.\nCString value;"), set())


class TestCStringBufferLifetime(unittest.TestCase):
    def test_unpaired_buffer_fails(self):
        findings = _findings("CString text; char* p = text.GetBuffer(8); Use(p);")
        self.assertTrue(any(kind == "buffer-lifetime" for kind, _ in findings))

    def test_paired_dot_and_arrow_buffers_pass(self):
        source = (
            "CString text; char* p = text.GetBufferSetLength(8); text.ReleaseBuffer(-1);\n"
            "CString* out; p = out->GetBuffer(4); out->ReleaseBuffer(4);\n"
        )
        self.assertEqual(_findings(source), set())

    def test_multiple_exit_releases_cover_one_acquisition(self):
        source = (
            "CString text; char* p = text.GetBuffer(8);\n"
            "if (Fail()) { text.ReleaseBuffer(0); return; }\n"
            "text.ReleaseBuffer(-1);\n"
        )
        self.assertEqual(_findings(source), set())


class TestCStringVarargs(unittest.TestCase):
    def test_nested_argument_split(self):
        self.assertEqual(
            split_call_arguments('ctx, &out, "[1]", static_cast<LPCSTR>(Make(a, b))'),
            ["ctx", "&out", '"[1]"', "static_cast<LPCSTR>(Make(a, b))"],
        )

    def test_bare_cstring_through_ellipsis_fails(self):
        source = (
            "CString templateText; CString replacement; CString out;\n"
            "scanBracketExpressions(ctx, &out, templateText, replacement);\n"
        )
        findings = _findings(source)
        self.assertTrue(any(kind == "varargs-object" for kind, _ in findings))

    def test_const_cstring_parameter_through_ellipsis_fails(self):
        source = (
            "void Expand(const CString& replacement) { CString out;\n"
            'scanBracketExpressions(ctx, &out, "[1]", replacement); }\n'
        )
        findings = _findings(source)
        self.assertTrue(any(kind == "varargs-object" for kind, _ in findings))

    def test_explicit_lpcstr_through_ellipsis_passes(self):
        source = (
            "CString templateText; CString replacement; CString out;\n"
            "scanBracketExpressions(ctx, &out, templateText, "
            "static_cast<LPCSTR>(replacement));\n"
        )
        self.assertEqual(_findings(source), set())

    def test_getbuffer_through_ellipsis_fails_even_with_release(self):
        source = (
            "CString templateText; CString replacement; CString out;\n"
            "scanBracketExpressions(ctx, &out, templateText, replacement.GetBuffer(0));\n"
            "replacement.ReleaseBuffer(-1);\n"
        )
        findings = _findings(source)
        self.assertTrue(any(kind == "varargs-object" for kind, _ in findings))


if __name__ == "__main__":
    unittest.main()
