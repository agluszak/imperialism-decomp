from __future__ import annotations

import unittest

from tools.reccmp.semantic_sweep import (
    CtorDtorIndex,
    callee_identity,
    classify_contract_row,
    defect_class,
    parse_ctor_dtor,
    sweep,
)


def _record_model() -> dict:
    return {
        "TGrand": {"bases": []},
        "TBase": {"bases": [{"type": "TGrand"}]},
        "TDerived": {"bases": [{"type": "TBase"}]},
        "TOther": {"bases": []},
    }


def _direct(address: str, arguments: list | None = None) -> dict:
    return {
        "kind": "direct",
        "target": {"function": address},
        "arguments": arguments or [],
    }


def _rows(calls_missing: list[dict], calls_extra: list[dict]) -> dict:
    return {
        "missing": [{"count": 1, "call": call} for call in calls_missing],
        "extra": [{"count": 1, "call": call} for call in calls_extra],
    }


class CalleeIdentityTests(unittest.TestCase):
    def test_virtual_identity_excludes_the_receiver(self):
        left = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["parameter", 0]},
        }
        right = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["load", 4, ["parameter", 2]]},
        }
        self.assertEqual(callee_identity(left), callee_identity(right))

    def test_indirect_targets_are_coarsened(self):
        left = {"kind": "indirect", "target": ["load", 4, ["parameter", 0]]}
        right = {"kind": "indirect", "target": ["load", 4, ["parameter", 3]]}
        self.assertEqual(callee_identity(left), callee_identity(right))

    def test_external_and_function_targets_are_distinct(self):
        external = {
            "kind": "direct",
            "target": {"external": {"library": "GDI32.DLL", "symbol": "GetRgnBox"}},
        }
        self.assertNotEqual(
            callee_identity(_direct("0x401000")), callee_identity(external)
        )


class ParseCtorDtorTests(unittest.TestCase):
    def test_parses_ctor_dtor_and_scalar_deleting_forms(self):
        self.assertEqual(parse_ctor_dtor("TBase::TBase"), ("TBase", "ctor"))
        self.assertEqual(parse_ctor_dtor("TBase::~TBase"), ("TBase", "dtor"))
        self.assertEqual(
            parse_ctor_dtor("TBase::`scalar deleting destructor'"),
            ("TBase", "dtor"),
        )
        self.assertIsNone(parse_ctor_dtor("TBase::DoWork"))
        self.assertIsNone(parse_ctor_dtor("FreeFunction"))


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.index = CtorDtorIndex(_record_model())
        self.names = {
            0x401000: "TBase::TBase",
            0x402000: "TGrand::TGrand",
            0x403000: "TOther::TOther",
            0x404000: "TUnknown::TUnknown",
            0x405000: "DoWork",
            0x406000: "DoMore",
        }

    def classify(self, row):
        return classify_contract_row(row, self.names, self.index)

    def test_same_identity_same_arity_is_suppressed_provenance(self):
        row = _rows(
            [_direct("0x405000", [["parameter", 1]])],
            [_direct("0x405000", [["parameter", 2]])],
        )
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"provenance_noise": 1})
        self.assertFalse(result["divergent"])

    def test_same_identity_different_arity_is_actionable(self):
        row = _rows(
            [_direct("0x405000", [["parameter", 1]])],
            [_direct("0x405000", [["parameter", 1], ["parameter", 2]])],
        )
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"same_callee_arity": 1})
        self.assertTrue(result["divergent"])

    def test_ctor_pair_on_same_chain_is_suppressed(self):
        row = _rows([_direct("0x402000")], [_direct("0x401000")])
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"inline_collapse_ctor_dtor": 1})
        self.assertFalse(result["divergent"])

    def test_ctors_of_unrelated_classes_are_wrong_callee(self):
        row = _rows([_direct("0x403000")], [_direct("0x401000")])
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"different_callee": 1})
        self.assertTrue(result["divergent"])

    def test_unknown_class_fails_open_as_chain_unverified(self):
        row = _rows([_direct("0x404000")], [_direct("0x401000")])
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"chain_unverified": 1})
        self.assertTrue(result["divergent"])

    def test_one_sided_ancestor_ctor_inside_derived_ctor_is_suppressed(self):
        row = {
            "name": "TDerived::TDerived",
            **_rows([_direct("0x402000")], []),
        }
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"inline_collapse_ctor_dtor": 1})
        self.assertFalse(result["divergent"])

    def test_one_sided_non_ctor_call_is_missing_logic(self):
        row = {"name": "TDerived::TDerived", **_rows([_direct("0x405000")], [])}
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"missing_call": 1})
        self.assertTrue(result["divergent"])

    def test_kind_flip_requires_identical_argument_lists(self):
        virtual = {
            "kind": "virtual",
            "target": {"slot": 8, "receiver": ["parameter", 0]},
            "arguments": [["parameter", 1]],
        }
        row = _rows([_direct("0x405000", [["parameter", 1]])], [virtual])
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"kind_flip": 1})
        self.assertFalse(result["divergent"] and "different_callee" in result["buckets"])
        different_args = dict(virtual, arguments=[["parameter", 2]])
        row = _rows([_direct("0x405000", [["parameter", 1]])], [different_args])
        result = self.classify(row)
        self.assertEqual(result["buckets"], {"different_callee": 1})

    def test_disabled_record_model_never_suppresses(self):
        index = CtorDtorIndex(None)
        row = _rows([_direct("0x402000")], [_direct("0x401000")])
        result = classify_contract_row(row, self.names, index)
        self.assertEqual(result["buckets"], {"chain_unverified": 1})
        self.assertTrue(result["divergent"])


class SweepPartitionTests(unittest.TestCase):
    def setUp(self):
        self.index = CtorDtorIndex(_record_model())

    @staticmethod
    def _entity(address: int, comparison: dict, name: str = "Fn") -> dict:
        return {
            "address": f"0x{address:x}",
            "name": name,
            "matching": 0.5,
            "comparison": comparison,
            "type": 1,
        }

    def run_sweep(self, reccmp, contract, ownership=None, datacmp=None):
        return sweep(
            reccmp,
            contract,
            names={},
            sizes={0x401000: 100, 0x402000: 900},
            ownership=ownership or {},
            datacmp_flags=datacmp or {},
            ctor_index=self.index,
        )

    def test_tier_truth_table(self):
        reccmp = {
            0x401000: self._entity(0x401000, {"status": "exact"}),
            0x402000: self._entity(
                0x402000,
                {"status": "mismatch", "difference": {"kind": "call_target"}},
            ),
            0x403000: self._entity(
                0x403000,
                {"status": "inconclusive", "inconclusive_reason": "alignment_failure"},
            ),
            0x404000: self._entity(
                0x404000,
                {
                    "status": "inconclusive",
                    "inconclusive_reason": "unsupported_control_flow",
                },
            ),
        }
        contract = {
            0x403000: {
                "original": "0x403000",
                "status": "mismatch",
                "reason": "call_contract",
                **_rows([_direct("0x405000")], []),
            },
            0x404000: {"original": "0x404000", "status": "pass"},
        }
        result = self.run_sweep(reccmp, contract)
        self.assertEqual(result["proven_clean"], 1)
        self.assertEqual(
            [row["address"] for row in result["tier1_proven_divergence"]],
            ["0x402000"],
        )
        self.assertEqual(
            [row["address"] for row in result["tier2_contract_divergence"]],
            ["0x403000"],
        )
        self.assertEqual(
            [row["address"] for row in result["tier3_no_verdict"]], ["0x404000"]
        )

    def test_suppressed_only_rows_never_reach_tier2(self):
        reccmp = {
            0x403000: self._entity(
                0x403000,
                {"status": "inconclusive", "inconclusive_reason": "alignment_failure"},
            ),
        }
        contract = {
            0x403000: {
                "original": "0x403000",
                "status": "mismatch",
                "reason": "call_contract",
                **_rows(
                    [_direct("0x405000", [["parameter", 1]])],
                    [_direct("0x405000", [["parameter", 2]])],
                ),
            }
        }
        result = self.run_sweep(reccmp, contract)
        self.assertEqual(result["tier2_contract_divergence"], [])
        self.assertEqual(len(result["suppressed_noise"]), 1)

    def test_library_rows_are_excluded_by_default(self):
        reccmp = {
            0x402000: self._entity(
                0x402000,
                {"status": "mismatch", "difference": {"kind": "call_target"}},
            )
        }
        result = self.run_sweep(reccmp, None, ownership={0x402000: "library"})
        self.assertEqual(result["tier1_proven_divergence"], [])

    def test_tier1_ranking_is_class_then_corroboration_then_size(self):
        reccmp = {
            0x401000: self._entity(
                0x401000,
                {"status": "mismatch", "difference": {"kind": "memory_value"}},
            ),
            0x402000: self._entity(
                0x402000,
                {"status": "mismatch", "difference": {"kind": "branch_condition"}},
            ),
            0x403000: self._entity(
                0x403000,
                {
                    "status": "mismatch",
                    "difference": {
                        "kind": "memory_value",
                        "orig": {"facts": {"symbol": "g_flagged"}},
                    },
                },
            ),
        }
        result = self.run_sweep(reccmp, None, datacmp={"g_flagged": "WARN"})
        self.assertEqual(
            [row["address"] for row in result["tier1_proven_divergence"]],
            ["0x402000", "0x403000", "0x401000"],
        )
        self.assertEqual(defect_class("branch_condition"), "wrong-control-flow")

    def test_missing_contract_report_degrades_to_tier3(self):
        reccmp = {
            0x403000: self._entity(
                0x403000,
                {"status": "inconclusive", "inconclusive_reason": "alignment_failure"},
            )
        }
        result = self.run_sweep(reccmp, None)
        self.assertEqual(
            [row["address"] for row in result["tier3_no_verdict"]], ["0x403000"]
        )


if __name__ == "__main__":
    unittest.main()
