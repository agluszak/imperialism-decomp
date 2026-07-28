from __future__ import annotations

import unittest

from reccmp.types import ImageId

from tools.semantic_calls import (
    DirectCallABI,
    ExpressionNormalizer,
    ExtractedCalls,
    _canonical_arithmetic,
    _canonical_direct_arguments,
    check_gate,
    compare_extracted_calls,
)


class FakeDataType:
    def __init__(self, name: str = "int", size: int = 4):
        self.name = name
        self.size = size

    def getName(self):
        return self.name

    def getLength(self):
        return self.size


class HighParam:
    def __init__(self, slot: int, data_type: FakeDataType | None = None):
        self.slot = slot
        self.data_type = data_type or FakeDataType()

    def getSlot(self):
        return self.slot

    def getDataType(self):
        return self.data_type


class FakeOp:
    def __init__(self, mnemonic: str, *inputs):
        self.mnemonic = mnemonic
        self.inputs = inputs

    def getMnemonic(self):
        return self.mnemonic

    def getNumInputs(self):
        return len(self.inputs)

    def getInput(self, index: int):
        return self.inputs[index]


class FakeVarnode:
    _next_offset = 0x100

    def __init__(
        self,
        *,
        value: int | None = None,
        size: int = 4,
        high=None,
        definition=None,
        address: bool = False,
    ):
        self.value = value
        self.size = size
        self.high = high
        self.definition = definition
        self.address = address
        self.unique_offset = FakeVarnode._next_offset
        FakeVarnode._next_offset += 1

    def getOffset(self):
        return self.value if self.value is not None else self.unique_offset

    def getAddress(self):
        return self

    def getSize(self):
        return self.size

    def hashCode(self):
        return id(self)

    def isConstant(self):
        return self.value is not None and not self.address

    def isAddress(self):
        return self.address

    def getHigh(self):
        return self.high

    def getDef(self):
        return self.definition


class SemanticCallTests(unittest.TestCase):
    def test_call_multiplicity_is_part_of_contract(self):
        call = {"kind": "direct", "target": {"function": "0x401000"}, "arguments": []}
        result = compare_extracted_calls(
            ExtractedCalls([call, call], []), ExtractedCalls([call], [])
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_count")
        self.assertEqual(result["call_count_status"], "mismatch")
        self.assertEqual(result["missing"], [{"count": 1, "call": call}])
        self.assertEqual(result["extra"], [])

    def test_changed_argument_provenance_is_mismatch(self):
        left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 1]],
        }
        right = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 2]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")
        self.assertEqual(result["call_count_status"], "pass")

    def test_unresolved_call_never_passes(self):
        result = compare_extracted_calls(
            ExtractedCalls([], ["0x1: unknown"]),
            ExtractedCalls([], ["0x2: unknown"]),
        )
        self.assertEqual(result["status"], "inconclusive")

    def test_zero_call_functions_pass(self):
        result = compare_extracted_calls(ExtractedCalls([], []), ExtractedCalls([], []))
        self.assertEqual(result["status"], "pass")

    def test_commutative_expression_order_is_normalized(self):
        left_param = FakeVarnode(high=HighParam(0))
        right_param = FakeVarnode(high=HighParam(1))
        left = FakeVarnode(definition=FakeOp("INT_ADD", left_param, right_param))
        right = FakeVarnode(definition=FakeOp("INT_ADD", right_param, left_param))
        normalizer = ExpressionNormalizer(None, ImageId.ORIG, {}, {})
        self.assertEqual(normalizer.normalize(left), normalizer.normalize(right))

    def test_copy_is_transparent_and_entity_addresses_are_mapped(self):
        address = FakeVarnode(value=0x500000, address=True)
        copied = FakeVarnode(definition=FakeOp("COPY", address))
        normalizer = ExpressionNormalizer(
            None, ImageId.RECOMP, {0x500000: (3, 0x600000)}, {}
        )
        self.assertEqual(
            normalizer.normalize(copied),
            ["entity", 3, "0x600000", 4],
        )

    def test_nominal_parameter_type_is_not_part_of_provenance(self):
        left = FakeVarnode(high=HighParam(2, FakeDataType("HMMIO", 4)))
        right = FakeVarnode(high=HighParam(2, FakeDataType("HMMIO__ *", 4)))
        normalizer = ExpressionNormalizer(None, ImageId.ORIG, {}, {})
        self.assertEqual(normalizer.normalize(left), normalizer.normalize(right))
        self.assertEqual(normalizer.normalize(left), ["parameter", 2, 4])

    def test_zero_offset_pointer_wrapper_is_transparent(self):
        parameter = FakeVarnode(high=HighParam(0))
        zero = FakeVarnode(value=0)
        wrapped = FakeVarnode(definition=FakeOp("PTRSUB", parameter, zero))
        normalizer = ExpressionNormalizer(None, ImageId.ORIG, {}, {})
        self.assertEqual(normalizer.normalize(wrapped), normalizer.normalize(parameter))

    def test_optional_direct_this_input_is_removed_from_explicit_arguments(self):
        target = {"function": "0x62246c"}
        receiver = ["parameter", 0, 4]
        explicit = ["constant", 4, 0]
        abis = {0x62246C: DirectCallABI(parameter_count=2, has_this=True)}
        self.assertEqual(
            _canonical_direct_arguments(target, [receiver, explicit], abis),
            [explicit],
        )
        self.assertEqual(
            _canonical_direct_arguments(target, [explicit], abis),
            [explicit],
        )

    def test_pointer_offsets_are_flattened_and_folded_at_storage_width(self):
        parameter = ["parameter", 0, 4]
        nested = _canonical_arithmetic(
            "INT_ADD",
            4,
            [
                _canonical_arithmetic(
                    "INT_ADD", 4, [parameter, ["constant", 4, 28]]
                ),
                ["constant", 4, 4],
            ],
        )
        self.assertEqual(
            nested,
            ["int_add", 4, ["constant", 4, 32], parameter],
        )
        self.assertEqual(
            _canonical_arithmetic(
                "INT_ADD",
                4,
                [["constant", 4, 0xFFFFFFFC], ["constant", 4, 4]],
            ),
            ["constant", 4, 0],
        )

    def test_address_outside_the_image_is_a_stable_literal(self):
        class EmptyMemory:
            def contains(self, _address):
                return False

        class EmptyProgram:
            def getMemory(self):
                return EmptyMemory()

        normalizer = ExpressionNormalizer(EmptyProgram(), ImageId.ORIG, {}, {})
        self.assertEqual(
            normalizer.normalize(FakeVarnode(value=0x500000, address=True)),
            ["address_literal", 4, 0x500000],
        )

    def test_ratchet_rejects_protected_regression_and_stale_debt(self):
        report = {
            "functions": [
                {"original": "0x1", "status": "mismatch"},
                {"original": "0x2", "status": "pass"},
                {"original": "0x3", "status": "mismatch"},
            ]
        }
        baseline = {
            "mode": "ratchet",
            "required": ["0x1", "0x2", "0x3"],
            "debt": ["0x1", "0x2"],
        }
        errors = check_gate(report, baseline)
        self.assertTrue(any("protected functions regressed: 0x3" in item for item in errors))
        self.assertTrue(any("semantic debt resolved" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
