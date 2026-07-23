from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.workflow.scalar_type_audit import collect_findings, render_report


class ScalarTypeAuditTests(unittest.TestCase):
    def test_findings_are_classified_and_source_located(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src/game").mkdir(parents=True)
            (root / "include/game").mkdir(parents=True)
            (root / "src/game/Test.cpp").write_text(
                "int f(int modeCode) {\n"
                "  int value = static_cast<int>(static_cast<short>(modeCode));\n"
                "  char flag = static_cast<char>(modeCode != 0);\n"
                "  return modeCode == 0x12 ? value : flag;\n"
                "}\n"
            )
            config = {
                "categories": {
                    "nested_integral_cast": {"classification": "width", "owner": "bd-a"},
                    "predicate_storage_cast": {"classification": "predicate", "owner": "bd-b"},
                    "raw_discriminant_literal": {"classification": "enum", "owner": "bd-c"},
                    "native_integral_boundary": {"classification": "native", "owner": "bd-d"},
                },
                "clang_tidy": {
                    "status": "test",
                    "decision": "advisory_only",
                    "evaluated_checks": [],
                    "rationale": "test",
                },
            }

            findings = collect_findings(root, config)

            self.assertEqual(
                {finding.category for finding in findings},
                {"nested_integral_cast", "predicate_storage_cast", "raw_discriminant_literal"},
            )
            self.assertTrue(all(finding.line > 0 for finding in findings))
            self.assertTrue(all(finding.owner for finding in findings))
            self.assertIn("Scalar type audit", render_report(findings, config))

    def test_pointer_null_checks_are_not_discriminants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src/game").mkdir(parents=True)
            (root / "include/game").mkdir(parents=True)
            (root / "include/game/Test.h").write_text(
                "struct Test {\n  TNation* nationState;\n};\n"
            )
            (root / "src/game/Test.cpp").write_text(
                "int f(Test* test, int modeCode) {\n"
                "  TMap* mapState = test->Lookup();\n"
                "  if (test->nationState == 0 || mapState != 0) {\n"
                "    return 0;\n"
                "  }\n"
                "  return modeCode != 0;\n"
                "}\n"
            )
            config = {
                "categories": {
                    "nested_integral_cast": {"classification": "width", "owner": "bd-a"},
                    "predicate_storage_cast": {"classification": "predicate", "owner": "bd-b"},
                    "raw_discriminant_literal": {"classification": "enum", "owner": "bd-c"},
                    "native_integral_boundary": {"classification": "native", "owner": "bd-d"},
                },
                "clang_tidy": {
                    "status": "test",
                    "decision": "advisory_only",
                    "evaluated_checks": [],
                    "rationale": "test",
                },
            }

            details = {finding.detail for finding in collect_findings(root, config)}

            # The header-declared member pointer and the .cpp-local pointer are both
            # null checks; only the genuine scalar discriminant is reported.
            self.assertEqual(details, {"modeCode != 0"})

    def test_native_boundaries_require_fingerprint_specific_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src/game").mkdir(parents=True)
            (root / "include/game").mkdir(parents=True)
            (root / "src/game/Test.cpp").write_text(
                "unsigned short f(int value) {\n"
                "  return static_cast<WORD>(value);\n"
                "}\n"
            )
            config = {
                "categories": {
                    "nested_integral_cast": {"classification": "width", "owner": "bd-a"},
                    "predicate_storage_cast": {"classification": "predicate", "owner": "bd-b"},
                    "raw_discriminant_literal": {"classification": "enum", "owner": "bd-c"},
                    "native_integral_boundary": {"classification": "native", "owner": "bd-d"},
                },
                "clang_tidy": {
                    "status": "test",
                    "decision": "advisory_only",
                    "evaluated_checks": [],
                    "rationale": "test",
                },
            }
            findings = collect_findings(root, config)
            self.assertEqual(len(findings), 1)

            with self.assertRaisesRegex(ValueError, "missing="):
                render_report(findings, config)

            config["native_integral_reviews"] = {
                findings[0].fingerprint: {
                    "classification": "win32_struct_word_field",
                    "evidence": "test evidence",
                }
            }
            report = render_report(findings, config)
            self.assertIn("win32_struct_word_field", report)
            self.assertIn("test evidence", report)

            config["native_integral_reviews"]["stale"] = {
                "classification": "stale",
                "evidence": "stale",
            }
            with self.assertRaisesRegex(ValueError, "stale=stale"):
                render_report(findings, config)


if __name__ == "__main__":
    unittest.main()
