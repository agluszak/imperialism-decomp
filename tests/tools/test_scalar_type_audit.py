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


if __name__ == "__main__":
    unittest.main()
