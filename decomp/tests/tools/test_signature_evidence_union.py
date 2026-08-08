"""Unit tests for the keyed signature-evidence union tool (Task 4).

Pure Python: builds evidence dicts in memory (as if loaded from the five/six
CSVs) and checks the union-row construction and the `explained` flag's logic,
plus a small end-to-end round-trip through real temp CSV files.
"""

import tempfile
import unittest
from pathlib import Path

from tools.ghidra.signature_evidence_union import (
    build_union_rows,
    load_evidence_files,
    write_union,
)


def _rows(*dicts):
    return {d["address"]: d for d in dicts}


class BuildUnionRowsTest(unittest.TestCase):
    def test_converged_structural_row_is_explained_even_alone(self):
        evidence = {"structural_audit": _rows(
            {"address": 0x1000, "name": "Foo::Bar", "category": "logical_converged",
             "abi_storage": "abi_storage_converged", "semantic": "semantically_converged"})}
        rows = build_union_rows(evidence)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["explained"])
        self.assertEqual(rows[0]["structural_category"], "logical_converged")

    def test_divergent_row_with_no_other_evidence_is_unexplained(self):
        evidence = {"structural_audit": _rows(
            {"address": 0x2000, "name": "Foo::Baz", "category": "convention_mismatch",
             "abi_storage": "", "semantic": ""})}
        rows = build_union_rows(evidence)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["explained"])

    def test_divergent_row_explained_by_a_queue(self):
        evidence = {
            "structural_audit": _rows(
                {"address": 0x2000, "name": "Foo::Baz", "category": "convention_mismatch",
                 "abi_storage": "", "semantic": ""}),
            "in_stack_queue": _rows(
                {"address": 0x2000, "name": "Foo::Baz", "reason": "dynamic_storage_insufficient:0x8",
                 "prototype": "void Foo::Baz(int)"}),
        }
        rows = build_union_rows(evidence)
        self.assertTrue(rows[0]["explained"])
        self.assertEqual(rows[0]["in_stack_queue_reason"],
                         "dynamic_storage_insufficient:0x8")

    def test_divergent_row_explained_by_datatype_hygiene(self):
        evidence = {
            "structural_audit": _rows(
                {"address": 0x3000, "name": "Foo::Qux", "category": "param_count_mismatch",
                 "abi_storage": "", "semantic": ""}),
            "datatype_hygiene": _rows(
                {"address": 0x3000, "name": "Foo::Qux", "category": "committed",
                 "type_resolution": "", "detail": "param:x:EmptyStub"}),
        }
        rows = build_union_rows(evidence)
        self.assertTrue(rows[0]["explained"])
        self.assertEqual(rows[0]["datatype_hygiene_category"], "committed")

    def test_address_present_only_in_a_queue_not_in_structural_audit(self):
        # missing_function rows never reach structural_audit's per-claim loop the
        # same way, or a queue-only address predates a structural-audit run --
        # either way, no structural row means nothing to explain.
        evidence = {"in_stack_queue": _rows(
            {"address": 0x4000, "name": "Foo::Quux", "reason": "missing_function",
             "prototype": "void Foo::Quux()"})}
        rows = build_union_rows(evidence)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["explained"])
        self.assertEqual(rows[0]["structural_category"], "")

    def test_name_falls_back_across_sources(self):
        evidence = {
            "structural_audit": _rows({"address": 0x5000, "name": "", "category": "converged",
                                       "abi_storage": "", "semantic": ""}),
            "in_stack_audit": _rows({"address": 0x5000, "name": "Foo::Named", "bucket": "source_owned"}),
        }
        rows = build_union_rows(evidence)
        self.assertEqual(rows[0]["name"], "Foo::Named")

    def test_rows_sorted_by_address(self):
        evidence = {"structural_audit": _rows(
            {"address": 0x9000, "name": "B", "category": "logical_converged", "abi_storage": "", "semantic": ""},
            {"address": 0x1000, "name": "A", "category": "logical_converged", "abi_storage": "", "semantic": ""},
        )}
        rows = build_union_rows(evidence)
        self.assertEqual([r["address"] for r in rows], [0x1000, 0x9000])


class LoadEvidenceFilesTest(unittest.TestCase):
    def test_missing_files_yield_empty_dicts_and_are_not_found_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            loaded, found = load_evidence_files(repo, {"structural_audit": "nope.csv"})
            self.assertEqual(loaded, {"structural_audit": {}})
            self.assertEqual(found, set())

    def test_reads_real_pipe_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            f = repo / "structural.csv"
            f.write_text(
                "address|name|category|type_resolution|detail|logical|abi_storage|semantic\n"
                "0x00401000|Foo::Bar|logical_converged|exact_complete|detail-text|"
                "logical_converged|abi_storage_converged|semantically_converged\n",
                encoding="utf-8",
            )
            loaded, found = load_evidence_files(repo, {"structural_audit": "structural.csv"})
            self.assertIn(0x00401000, loaded["structural_audit"])
            self.assertEqual(loaded["structural_audit"][0x00401000]["name"], "Foo::Bar")
            self.assertEqual(found, {"structural_audit"})

    def test_present_but_empty_file_is_found_on_disk_not_missing(self):
        # A legitimately empty audit (e.g. datatype_hygiene.csv with zero
        # opaque-by-value issues) must NOT be reported as "not found" -- it exists,
        # it just has no data rows.
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            f = repo / "empty.csv"
            f.write_text("address|name|category|type_resolution|detail\n", encoding="utf-8")
            loaded, found = load_evidence_files(repo, {"datatype_hygiene": "empty.csv"})
            self.assertEqual(loaded["datatype_hygiene"], {})
            self.assertEqual(found, {"datatype_hygiene"})


class WriteUnionRoundTripTest(unittest.TestCase):
    def test_write_then_reload_matches(self):
        rows = [{
            "address": 0x1234, "name": "Foo::Bar", "structural_category": "logical_converged",
            "structural_abi": "abi_storage_converged", "structural_semantic": "semantically_converged",
            "in_stack_queue_reason": "", "divergent_queue_reason": "", "packed_queue_reason": "",
            "datatype_hygiene_category": "", "in_stack_audit_bucket": "source_owned",
            "explained": True,
        }]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "union.csv"
            write_union(rows, out)
            text = out.read_text(encoding="utf-8")
            self.assertIn("0x00001234|Foo::Bar", text)
            self.assertIn("|true", text)


if __name__ == "__main__":
    unittest.main()
