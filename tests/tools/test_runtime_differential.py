#!/usr/bin/env python3
"""Contracts for normalized OG/recomp trace comparison."""

from __future__ import annotations

import unittest

from tools.runtime.differential import first_divergence


class DifferentialTraceTests(unittest.TestCase):
    def test_equal_traces_have_no_divergence(self) -> None:
        trace = [{"seq": 0, "probe": "p", "occurrence": 1, "fields": {"event": 1}}]
        self.assertIsNone(first_divergence(trace, list(trace)))

    def test_first_semantic_mismatch_is_reported(self) -> None:
        original = [
            {"seq": 0, "probe": "p", "occurrence": 1, "fields": {"event": 1}},
            {"seq": 1, "probe": "p", "occurrence": 2, "fields": {"event": 2}},
        ]
        recomp = [
            {"seq": 0, "probe": "p", "occurrence": 1, "fields": {"event": 1}},
            {"seq": 1, "probe": "p", "occurrence": 2, "fields": {"event": 3}},
        ]
        mismatch = first_divergence(original, recomp)
        self.assertEqual(mismatch["index"], 1)
        self.assertEqual(mismatch["original"]["fields"]["event"], 2)
        self.assertEqual(mismatch["recomp"]["fields"]["event"], 3)


if __name__ == "__main__":
    unittest.main()
