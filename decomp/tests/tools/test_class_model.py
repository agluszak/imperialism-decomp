"""Tests for the class model (AST record walk) and layout-oracle generation/parse.

Pure Python — synthetic AST nodes shaped like clang's -ast-dump=json output, and
string-level checks on the generated oracle TU. The MSVC500 compile itself is
covered by running the real oracle (build evidence), not unit-testable here.
"""

import tempfile
import unittest
from pathlib import Path

from tools.class_model import (
    BaseInfo,
    FieldInfo,
    RecordInfo,
    _array_count,
    _walk_records,
)
from tools.clang_ast_index import game_header_include_paths
from tools.layout_oracle import generate_oracle_tu, parse_oracle_output


def _field(name, qual, bitfield=False):
    d = {"kind": "FieldDecl", "name": name, "type": {"qualType": qual}}
    if bitfield:
        d["isBitfield"] = True
    return d


def _record(name, *inner, bases=None, complete=True, file=None):
    d = {"kind": "CXXRecordDecl", "name": name, "tagUsed": "class", "inner": list(inner)}
    if complete:
        d["completeDefinition"] = True
    if bases:
        d["bases"] = bases
    if file:
        d["loc"] = {"file": file}
    return d


def _walk(tu, prefix="include/"):
    out = {}
    _walk_records(tu, [], [""], out, prefix)
    return out


class WalkRecordsTest(unittest.TestCase):
    def test_collects_fields_bases_virtuals(self):
        tu = {"kind": "TranslationUnitDecl", "inner": [_record(
            "TArmyMission",
            _field("field_14", "short"),
            _field("resourceWeights", "float[5]"),
            {"kind": "CXXMethodDecl", "name": "Tick", "virtual": True},
            bases=[{"type": {"qualType": "TMission"}, "access": "public"}],
            file="/repo/include/game/TArmyMission.h")]}
        out = _walk(tu)
        rec = out["TArmyMission"]
        self.assertEqual([f.name for f in rec.fields], ["field_14", "resourceWeights"])
        self.assertEqual(rec.fields[1].array_count, 5)
        self.assertEqual(rec.bases, [BaseInfo("TMission", "public", False)])
        self.assertTrue(rec.has_own_virtuals)

    def test_forward_decl_not_collected(self):
        tu = {"kind": "TranslationUnitDecl", "inner": [
            _record("TFwd", complete=False, file="/repo/include/game/x.h")]}
        self.assertEqual(_walk(tu), {})

    def test_out_of_prefix_not_collected(self):
        tu = {"kind": "TranslationUnitDecl", "inner": [
            _record("CWnd", _field("m_hWnd", "HWND"), file="/msvc/mfc/afxwin.h")]}
        self.assertEqual(_walk(tu), {})

    def test_sparse_file_tracking(self):
        # Second record carries no loc; inherits the current file in doc order.
        tu = {"kind": "TranslationUnitDecl", "inner": [
            _record("A", _field("x", "int"), file="/repo/include/game/a.h"),
            _record("B", _field("y", "int"))]}
        out = _walk(tu)
        self.assertIn("B", out)
        self.assertEqual(out["B"].file, "include/game/a.h")

    def test_template_pattern_skipped(self):
        tu = {"kind": "TranslationUnitDecl", "inner": [{
            "kind": "ClassTemplateDecl", "name": "TList",
            "inner": [_record("TList", _field("head", "T *"),
                              file="/repo/include/game/t.h")]}]}
        self.assertEqual(_walk(tu), {})

    def test_bitfield_flagged(self):
        tu = {"kind": "TranslationUnitDecl", "inner": [_record(
            "F", _field("bits", "unsigned int", bitfield=True),
            file="/repo/include/game/f.h")]}
        self.assertTrue(_walk(tu)["F"].fields[0].is_bitfield)

    def test_invalid_recovery_field_skipped(self):
        invalid = _field("BOOL", "int")
        invalid["isInvalid"] = True
        tu = {"kind": "TranslationUnitDecl", "inner": [_record(
            "CIncludeView", invalid, _field("m_field44", "int"),
            file="/repo/include/game/CIncludeView.h")]}
        self.assertEqual([f.name for f in _walk(tu)["CIncludeView"].fields], ["m_field44"])


class ArrayCountTest(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(_array_count("short"), 0)
        self.assertEqual(_array_count("float[5]"), 5)
        self.assertEqual(_array_count("char[3][4]"), 12)


class OracleGenerationTest(unittest.TestCase):
    def _model(self):
        rec = RecordInfo("TFoo", "class", "include/game/TFoo.h")
        rec.bases = [BaseInfo("TBase"), BaseInfo("TVirt", is_virtual=True)]
        rec.fields = [FieldInfo("x", "int"), FieldInfo("bits", "unsigned int", is_bitfield=True),
                      FieldInfo("r", "int &")]
        return {"TFoo": rec}

    def test_tu_measures_only_measurable(self):
        cpp, skipped = generate_oracle_tu(self._model(), Path("/nonexistent"))
        self.assertIn('printf("RECORD|TFoo|', cpp)
        self.assertIn('printf("BASE|TFoo|TBase|', cpp)
        self.assertIn('printf("FIELD|TFoo|x|', cpp)
        # bitfield / reference / virtual base are skipped, not measured
        self.assertNotIn("FIELD|TFoo|bits", cpp)
        self.assertNotIn("FIELD|TFoo|r|", cpp)
        self.assertNotIn("BASE|TFoo|TVirt", cpp)
        self.assertEqual(sorted(skipped["TFoo"]),
                         ["bitfield:bits", "reference:r", "virtual_base:TVirt"])

    def test_access_widening_precedes_includes(self):
        cpp, _ = generate_oracle_tu(self._model(), Path("/nonexistent"))
        self.assertLess(cpp.index("#define private public"), cpp.index("#include <stdio.h>"))

    def test_nested_game_headers_use_canonical_include_spelling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "include" / "game" / "ui_core" / "TView.h"
            nested.parent.mkdir(parents=True)
            nested.write_text("#pragma once\n", encoding="utf-8")
            top = root / "include" / "game" / "TObject.h"
            top.write_text("#pragma once\n", encoding="utf-8")
            self.assertEqual(
                game_header_include_paths(root),
                ["game/TObject.h", "game/ui_core/TView.h"],
            )


class OracleParseTest(unittest.TestCase):
    def test_roundtrip(self):
        raw = ("RECORD|TFoo|24\nBASE|TFoo|TBase|0\nFIELD|TFoo|x|8|4\n"
               "EXTBASE|CView|0x0\nEXTBASE|CWnd|64\nnoise line\n")
        out, ext, mfc = parse_oracle_output(raw.replace("0x0", "84"))
        self.assertEqual(out["TFoo"]["size"], 24)
        self.assertEqual(out["TFoo"]["bases"], {"TBase": 0})
        self.assertEqual(out["TFoo"]["fields"]["x"], {"offset": 8, "size": 4})
        self.assertEqual(ext, {"CView": 84, "CWnd": 64})
        self.assertEqual(mfc, {})

    def test_mfc_value_lines(self):
        out, ext, mfc = parse_oracle_output("MFCVALUE|CPoint|8\nMFCFIELD|CPoint|x|0|4\nMFCFIELD|CPoint|y|4|4\n")
        self.assertEqual(mfc["CPoint"]["size"], 8)
        self.assertEqual(mfc["CPoint"]["fields"]["y"], {"offset": 4, "size": 4})


if __name__ == "__main__":
    unittest.main()
