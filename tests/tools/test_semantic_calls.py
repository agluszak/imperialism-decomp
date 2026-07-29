from __future__ import annotations

import unittest

from reccmp.types import ImageId

from tools.semantic_calls import (
    DirectCallABI,
    ExpressionNormalizer,
    ExtractedCalls,
    _canonical_arithmetic,
    _canonical_call_value,
    _canonical_direct_arguments,
    _direct_call_abis,
    _normalized_virtual_target,
    _reccmp_proves_call_contract,
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


class FakeAddressFactory:
    def getAddress(self, value):
        return value


class FakeParameter:
    def __init__(self, name: str, auto: bool = False):
        self.name = name
        self.auto = auto

    def getName(self):
        return self.name

    def isAutoParameter(self):
        return self.auto


class FakeFunction:
    def __init__(self, parameters, thunked=None):
        self.parameters = parameters
        self.thunked = thunked

    def getParameters(self):
        return self.parameters

    def getThunkedFunction(self, _recursive):
        return self.thunked


class FakeFunctionManager:
    def __init__(self, function):
        self.function = function

    def getFunctionAt(self, address):
        if isinstance(self.function, dict):
            return self.function[int(address, 0)]
        return self.function


class FakeProgram:
    def __init__(self, function):
        self.function = function

    def getFunctionManager(self):
        return FakeFunctionManager(self.function)

    def getAddressFactory(self):
        return FakeAddressFactory()


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

    def test_normalized_vtable_slot_is_recognized_as_virtual(self):
        receiver = ["parameter", 0, 4]
        target = [
            "load",
            4,
            [
                "int_add",
                4,
                ["constant", 4, 308],
                ["load", 4, receiver],
            ],
        ]
        self.assertEqual(_normalized_virtual_target(target), (receiver, 308))

    def test_normalized_function_pointer_is_not_treated_as_virtual(self):
        target = [
            "load",
            4,
            ["int_add", 4, ["constant", 4, 8], ["parameter", 0, 4]],
        ]
        self.assertIsNone(_normalized_virtual_target(target))

    def test_completed_reccmp_proof_precedes_heuristic_pcode(self):
        self.assertTrue(_reccmp_proves_call_contract({"status": "exact"}))
        self.assertTrue(_reccmp_proves_call_contract({"status": "effective"}))
        self.assertFalse(_reccmp_proves_call_contract({"status": "mismatch"}))
        self.assertFalse(_reccmp_proves_call_contract({"status": "inconclusive"}))
        self.assertFalse(_reccmp_proves_call_contract(None))

    def test_call_result_nominal_width_is_not_part_of_contract(self):
        target = {"receiver": ["parameter", 0, 4], "virtual_slot": 172}
        narrow = ["call_result", target, [], 1]
        wide = ["call_result", target, [], 4]
        self.assertEqual(_canonical_call_value(narrow), _canonical_call_value(wide))

    def test_indirect_piece_filler_around_call_result_is_transparent(self):
        result = ["call_result", {"function": "0x401000"}, [], 1]
        filler = [
            "indirect",
            3,
            ["constant", 3, 0],
            ["constant", 4, 20],
        ]
        self.assertEqual(
            _canonical_call_value(["piece", 4, filler, result]),
            _canonical_call_value(result),
        )

    def test_stale_upper_register_piece_is_transparent(self):
        low = ["int_add", 2, ["constant", 2, 1], ["parameter", 1, 2]]
        stale_upper = [
            "subpiece",
            2,
            [
                "int_right",
                4,
                ["register", "eax", 4],
                ["constant", 4, 16],
            ],
            ["constant", 4, 0],
        ]
        self.assertEqual(
            _canonical_call_value(["piece", 4, stale_upper, low]),
            _canonical_call_value(low),
        )

    def test_arithmetic_is_resorted_after_call_result_width_is_removed(self):
        call = ["call_result", {"function": "0x401000"}, [], 4]
        left = ["int_add", 4, ["constant", 4, 60], call]
        right = ["int_add", 4, call, ["constant", 4, 60]]
        self.assertEqual(_canonical_call_value(left), _canonical_call_value(right))

    def test_argument_array_is_canonicalized_without_treating_it_as_an_expression(self):
        arguments = [["parameter", 1, 4], ["constant", 4, 0]]
        self.assertEqual(_canonical_call_value(arguments), arguments)

    def test_multiequal_width_is_derived_from_uniform_operands(self):
        narrow = [
            "multiequal",
            2,
            ["constant", 2, 1],
            ["constant", 2, 2],
        ]
        nominally_wide = [
            "multiequal",
            4,
            ["constant", 2, 1],
            ["constant", 2, 2],
        ]
        self.assertEqual(
            _canonical_call_value(narrow),
            _canonical_call_value(nominally_wide),
        )

    def test_boolean_zero_extension_is_transparent(self):
        predicate = [
            "int_notequal",
            1,
            ["constant", 1, 0],
            ["load", 1, ["parameter", 0, 4]],
        ]
        self.assertEqual(
            _canonical_call_value(["int_zext", 4, predicate]),
            _canonical_call_value(predicate),
        )

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

    def test_direct_call_abi_uses_thunk_target_parameters(self):
        target = FakeFunction(
            [FakeParameter("this", auto=True), FakeParameter("value")]
        )
        thunk = FakeFunction([], thunked=target)
        self.assertEqual(
            _direct_call_abis(FakeProgram(thunk), {0x401000: 0x401000}),
            {0x401000: DirectCallABI(parameter_count=2, has_this=True)},
        )

    def test_direct_call_abi_prefers_canonical_entry_over_folded_alias(self):
        canonical = FakeFunction([FakeParameter("this", auto=True)])
        alias = FakeFunction([])
        program = FakeProgram({0x48F250: canonical, 0x570850: alias})
        self.assertEqual(
            _direct_call_abis(
                program,
                {0x48F250: 0x48F250, 0x570850: 0x48F250},
            ),
            {0x48F250: DirectCallABI(parameter_count=1, has_this=True)},
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
