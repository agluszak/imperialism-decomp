#!/usr/bin/env python3
"""Unit tests for the agent-rules KB linter (tools.workflow.check_agent_rules).

Focus: the superseded/superseded_by validation path, which the real
config/agent_rules.yml has never exercised (all 30+ rules are active). These
tests keep that branch honest so a future first-superseded rule is validated.
"""

from __future__ import annotations

import unittest

from tools.workflow.check_agent_rules import lint_rules

SKILLS = {"decomp-loop", "quality-control"}
TAGS = {"thiscall", "cstring"}


def _lint(rules):
    return lint_rules(rules, known_skills=SKILLS, known_tags=TAGS)


class SupersedeValidationTest(unittest.TestCase):
    def test_active_baseline_passes(self):
        self.assertEqual(_lint([{"id": "AAA-B-001", "status": "active"}]), [])

    def test_superseded_pointing_at_active_passes(self):
        rules = [
            {"id": "AAA-B-001", "status": "active"},
            {"id": "AAA-B-002", "status": "superseded", "superseded_by": "AAA-B-001"},
        ]
        self.assertEqual(_lint(rules), [])

    def test_superseded_without_pointer_fails(self):
        rules = [
            {"id": "AAA-B-001", "status": "active"},
            {"id": "AAA-B-002", "status": "superseded"},
        ]
        failures = _lint(rules)
        self.assertTrue(any("superseded without superseded_by" in f for f in failures), failures)

    def test_superseded_by_unknown_id_fails(self):
        rules = [
            {"id": "AAA-B-001", "status": "active"},
            {"id": "AAA-B-002", "status": "superseded", "superseded_by": "AAA-B-099"},
        ]
        failures = _lint(rules)
        self.assertTrue(any("is not an active rule" in f for f in failures), failures)

    def test_superseded_by_another_superseded_rule_fails(self):
        # A superseded rule may not point at a rule that is itself superseded.
        rules = [
            {"id": "AAA-B-001", "status": "superseded", "superseded_by": "AAA-B-002"},
            {"id": "AAA-B-002", "status": "superseded", "superseded_by": "AAA-B-001"},
        ]
        failures = _lint(rules)
        self.assertEqual(sum("is not an active rule" in f for f in failures), 2, failures)

    def test_bad_status_fails(self):
        failures = _lint([{"id": "AAA-B-001", "status": "retired"}])
        self.assertTrue(any("status must be active|superseded" in f for f in failures), failures)


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
            "skill": "quality-control",
            "triggers": ["thiscall"],
        }]
        self.assertEqual(_lint(rules), [])


if __name__ == "__main__":
    unittest.main()
