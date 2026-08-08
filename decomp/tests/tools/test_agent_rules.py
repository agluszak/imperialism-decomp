#!/usr/bin/env python3
"""Unit tests for the agent-rules KB linter."""

from __future__ import annotations

import unittest

from tools.workflow.check_agent_rules import lint_rules

SKILLS = {"decompile-function", "verify"}
TAGS = {"thiscall", "cstring"}


def _lint(rules):
    return lint_rules(rules, known_skills=SKILLS, known_tags=TAGS)


class SupersedeValidationTest(unittest.TestCase):
    def test_active_baseline_passes(self):
        self.assertEqual(_lint([{"id": "AAA-B-001", "status": "active"}]), [])

    def test_bad_status_fails(self):
        failures = _lint([{"id": "AAA-B-001", "status": "retired"}])
        self.assertTrue(any("status must be active" in f for f in failures), failures)


class OtherValidationsTest(unittest.TestCase):
    def test_bad_id_shape_fails(self):
        failures = _lint([{"id": "lowercase-1", "status": "active"}])
        self.assertTrue(any("does not match" in f for f in failures), failures)

    def test_duplicate_id_fails(self):
        rules = [
            {"id": "AAA-B-001", "status": "active"},
            {"id": "AAA-B-001", "status": "active"},
        ]
        failures = _lint(rules)
        self.assertTrue(any("duplicate id" in f for f in failures), failures)

    def test_out_of_order_suffix_fails(self):
        rules = [
            {"id": "AAA-B-005", "status": "active"},
            {"id": "AAA-B-002", "status": "active"},
        ]
        failures = _lint(rules)
        self.assertTrue(any("out of order" in f for f in failures), failures)

    def test_required_forbidden_overlap_fails(self):
        rules = [{"id": "AAA-B-001", "status": "active", "required": ["x"], "forbidden": ["x"]}]
        failures = _lint(rules)
        self.assertTrue(any("required and forbidden overlap" in f for f in failures), failures)

    def test_non_just_tool_fails(self):
        rules = [{"id": "AAA-B-001", "status": "active", "tools": ["uv run python -m foo"]}]
        failures = _lint(rules)
        self.assertTrue(any("is not a `just` command" in f for f in failures), failures)

    def test_unknown_skill_fails(self):
        rules = [{"id": "AAA-B-001", "status": "active", "skill": "no-such-skill"}]
        failures = _lint(rules)
        self.assertTrue(any("does not exist under" in f for f in failures), failures)

    def test_underivable_trigger_fails(self):
        rules = [{"id": "AAA-B-001", "status": "active", "triggers": ["not_a_real_tag"]}]
        failures = _lint(rules)
        self.assertTrue(any("is not derivable" in f for f in failures), failures)

    def test_known_skill_and_trigger_pass(self):
        rules = [{
            "id": "AAA-B-001",
            "status": "active",
            "skill": "verify",
            "triggers": ["thiscall"],
        }]
        self.assertEqual(_lint(rules), [])


if __name__ == "__main__":
    unittest.main()


class ToolTargetExistenceTest(unittest.TestCase):
    """bd imperialism-decomp-g7z6: `just advice` was handing agents a deleted target.

    Being `just`-shaped is not the same as being real. GEN-NOHAND-018 recommended
    `just regen-stubs` long after that recipe was folded into `just build`, so an agent
    following the rule got an error instead of the workflow it teaches.
    """

    def test_dead_target_is_rejected(self):
        rules = [{"id": "AAA-B-001", "status": "active", "tools": ["just no-such-target-xyz"]}]
        failures = _lint(rules)
        self.assertTrue(
            any("does not exist" in failure for failure in failures),
            f"expected a dead-target failure, got {failures}",
        )

    def test_live_target_passes(self):
        self.assertEqual(_lint([{"id": "AAA-B-001", "status": "active", "tools": ["just build"]}]), [])

    def test_target_with_arguments_is_checked_on_the_recipe_name_only(self):
        # Arguments are the rule author's business; only the recipe name is checkable.
        rules = [{"id": "AAA-B-001", "status": "active", "tools": ["just compare 0x49ace0"]}]
        self.assertEqual(_lint(rules), [])

    def test_non_just_tool_is_still_rejected_without_a_target_lookup(self):
        rules = [{"id": "AAA-B-001", "status": "active", "tools": ["python -m tools.x"]}]
        failures = _lint(rules)
        self.assertTrue(any("is not a `just` command" in failure for failure in failures))
        self.assertFalse(any("does not exist" in failure for failure in failures))
