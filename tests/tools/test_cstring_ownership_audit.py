"""Tests for the VC5-backed CString ownership and raw-span audit."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.class_model import BaseInfo, FieldInfo, RecordInfo
from tools.workflow.cstring_ownership_audit import (
    _clone_owner,
    scan_raw_spans,
    snapshot_rows,
    validate_reviews,
    validate_snapshot,
)


def _model() -> dict[str, RecordInfo]:
    root = RecordInfo("TObject", "class", "include/game/TObject.h")
    record = RecordInfo("TRecord", "class", "include/game/TRecord.h")
    record.bases = [BaseInfo("TObject")]
    record.fields = [FieldInfo("prefix", "int"), FieldInfo("name", "CString")]
    return {"TObject": root, "TRecord": record}


def _layout() -> dict:
    return {
        "layouts": {
            "TRecord": {
                "size": 12,
                "bases": {"TObject": 0},
                "fields": {
                    "prefix": {"offset": 4, "size": 4},
                    "name": {"offset": 8, "size": 4},
                },
            }
        }
    }


class CStringLayoutSnapshotTest(unittest.TestCase):
    def test_uses_physical_offsets_and_detects_semantic_drift(self):
        model = _model()
        rows = snapshot_rows(model, _layout())
        name = next(row for row in rows if row.field == "name")
        self.assertEqual((name.offset, name.size, name.storage), (8, 4, "embedded"))
        self.assertEqual(validate_snapshot(rows, model), [])

        model["TRecord"].fields.insert(0, FieldInfo("newField", "short"))
        errors = validate_snapshot(rows, model)
        self.assertTrue(any("layout-affecting declaration changed" in error for error in errors))


class CStringCloneReviewTest(unittest.TestCase):
    def test_inherited_raw_clone_owner_requires_review(self):
        model = _model()
        self.assertEqual(_clone_owner("TRecord", model), "TObject")
        errors = validate_reviews(model, {})
        self.assertTrue(any("clone review inventory changed" in error for error in errors))


class CStringRawSpanTest(unittest.TestCase):
    def _scan(self, source: str):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "src" / "game"
            source_dir.mkdir(parents=True)
            (source_dir / "Probe.cpp").write_text(source, encoding="utf-8")
            return scan_raw_spans(root, snapshot_rows(_model(), _layout()), _model())

    def test_span_ending_before_cstring_is_safe_boundary(self):
        spans = self._scan(
            "void Read(TStream* stream) { TRecord* record; "
            "stream->ReadBytes(record, 8); }"
        )
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].verdict, "safe_boundary")

    def test_span_crossing_cstring_is_rejected(self):
        spans = self._scan(
            "void Read(TStream* stream) { TRecord* record; "
            "stream->ReadBytes(record, 12); }"
        )
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].verdict, "crosses_cstring")
        self.assertIn("name", spans[0].detail)


if __name__ == "__main__":
    unittest.main()
