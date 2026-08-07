"""Contracts for the complete local verification schedule."""

import json
from pathlib import Path
import subprocess
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


class PrecommitWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        completed = subprocess.run(
            ["just", "--dump", "--dump-format", "json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        cls.dump = json.loads(completed.stdout)

    def test_parallel_groups_keep_the_complete_verification_surface(self) -> None:
        recipes = self.dump["recipes"]
        expected_dependencies = {
            "_precommit-after-build": {
                "_precommit-post-build-checks",
                "_precommit-runtime-check",
            },
            "_precommit-post-build-checks": {
                "gates",
                "_precommit-independent-checks",
            },
            "_precommit-independent-checks": {
                "cstring-runtime-probe",
                "runtime-harness-lint",
                "lint-warning-gate-test",
                "test",
                "_precommit-generated-integrity-gate",
            },
        }
        for name, expected in expected_dependencies.items():
            recipe = recipes[name]
            self.assertIn("parallel", recipe["attributes"])
            self.assertEqual(
                {dependency["recipe"] for dependency in recipe["dependencies"]},
                expected,
            )

        runtime_body = "\n".join(
            line[0] for line in recipes["_precommit-runtime-check"]["body"]
        )
        self.assertIn("runtime-check pr --jobs 1", runtime_body)

    def test_lint_option_sets_use_distinct_cmake_caches(self) -> None:
        assignments = self.dump["assignments"]
        directories = {
            assignments[name]["value"]
            for name in (
                "lint_build_dir",
                "runtime_lint_build_dir",
                "lint_warning_test_build_dir",
            )
        }
        self.assertEqual(len(directories), 3)


if __name__ == "__main__":
    unittest.main()
