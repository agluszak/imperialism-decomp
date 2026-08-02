#!/usr/bin/env python3
"""Contracts for the isolated population-eating retail differential."""

from __future__ import annotations

import unittest

from tools.runtime.population_eating_differential import (
    FIXTURES,
    _first_difference,
    _predictor_failure,
)


class PopulationEatingDifferentialTests(unittest.TestCase):
    def test_fixture_matrix_exhausts_small_stocks_and_labor_compositions(self) -> None:
        small = [fixture for fixture in FIXTURES if fixture.population <= 4]
        self.assertEqual(len(small), 1120)
        self.assertEqual({fixture.population for fixture in small}, set(range(5)))
        self.assertTrue(all(sum(fixture.labor) == fixture.population for fixture in small))
        self.assertEqual({fixture.stocks for fixture in small}, {
            tuple((mask >> index) & 1 for index in range(5)) for mask in range(32)
        })

    def test_predictor_contract_requires_no_mutation_and_equal_outputs(self) -> None:
        observation = {
            "pretend": {"substitution_count": 2, "starvation_loss": 3, "input_unchanged": True},
            "eat": {"substitution_count": 2, "starvation_loss": 3},
        }
        self.assertIsNone(_predictor_failure(observation))
        observation["pretend"]["starvation_loss"] = 4
        self.assertEqual(_predictor_failure(observation)["field"], "starvation_loss")

    def test_first_difference_names_nested_field(self) -> None:
        self.assertEqual(
            _first_difference({"labor": {"baseline": [1, 2, 3]}}, {"labor": {"baseline": [1, 9, 3]}}),
            {"path": "$.labor.baseline[1]", "retail": 2, "recomp": 9},
        )


if __name__ == "__main__":
    unittest.main()
