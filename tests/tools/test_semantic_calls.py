from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from reccmp.types import ImageId

from tools.semantic_calls import (
    AUDIT_REPORT_RELATIVE_PATH,
    CACHE_KEEP_COUNT,
    REPORT_RELATIVE_PATH,
    DepRecorder,
    DirectCallABI,
    ExpressionNormalizer,
    ExtractedCalls,
    FunctionPair,
    ReuseContext,
    _asymmetric_arity_targets,
    _attach_reuse_records,
    _canonical_arithmetic,
    _canonical_call_value,
    _canonical_direct_arguments,
    _direct_call_abis,
    _dep_matches,
    _diff_reports,
    _encode_dep,
    _full_report_relative_path,
    _load_orig_calls_cache,
    _normalize_frame_slots,
    _normalized_virtual_target,
    _orig_calls_entry,
    _prune_stale_caches,
    _restore_orig_calls,
    _virtual_target,
    _prune_targeted_reports,
    _reccmp_proves_call_contract,
    _row_reusable,
    check_gate,
    compare_extracted_calls,
    extract_calls,
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


class FakeEntryPoint:
    def __init__(self, offset: int):
        self.offset = offset

    def getOffset(self):
        return self.offset


class FakeFunction:
    def __init__(self, parameters, thunked=None, varargs=False, name="fn", entry=0):
        self.parameters = parameters
        self.thunked = thunked
        self.varargs = varargs
        self.name = name
        self.entry = entry

    def getParameters(self):
        return self.parameters

    def getThunkedFunction(self, _recursive):
        return self.thunked

    def hasVarArgs(self):
        return self.varargs

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return FakeEntryPoint(self.entry)

    def isExternal(self):
        return False


class FakeFunctionManager:
    def __init__(self, function):
        self.function = function

    def getFunctionAt(self, address):
        if isinstance(self.function, dict):
            return self.function[int(address, 0)]
        return self.function


class FakeRegister:
    def __init__(self, name: str):
        self.name = name

    def getName(self):
        return self.name


class FakeProgram:
    def __init__(self, function, register_name: str | None = None):
        self.function = function
        self.register_name = register_name

    def getFunctionManager(self):
        return FakeFunctionManager(self.function)

    def getAddressFactory(self):
        return FakeAddressFactory()

    def getRegister(self, _address, _size):
        return FakeRegister(self.register_name) if self.register_name else None


class HighParam:
    def __init__(self, slot: int, data_type: FakeDataType | None = None):
        self.slot = slot
        self.data_type = data_type or FakeDataType()

    def getSlot(self):
        return self.slot

    def getDataType(self):
        return self.data_type


class FakeSeqnum:
    def getTarget(self):
        return "0x1000"


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

    def getSeqnum(self):
        return FakeSeqnum()


class FakeHighFunction:
    def __init__(self, ops):
        self.ops = ops

    def getPcodeOps(self):
        return list(self.ops)


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
        register: bool = False,
    ):
        self.value = value
        self.size = size
        self.high = high
        self.definition = definition
        self.address = address
        self.register = register
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
        return self.value is not None and not self.address and not self.register

    def isRegister(self):
        return self.register

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

    def test_stale_upper_piece_exposed_by_indirect_dissolution(self):
        low = ["subpiece", 1, ["int_right", 4, ["parameter", 1, 4], ["constant", 4, 24]], ["constant", 4, 0]]
        stale_upper = [
            "subpiece",
            1,
            ["int_right", 4, ["parameter", 1, 4], ["constant", 4, 16]],
            ["constant", 4, 0],
        ]
        wrapped_upper = ["indirect", 1, stale_upper, ["constant", 4, 0x40]]
        for upper in (stale_upper, wrapped_upper):
            self.assertEqual(
                _canonical_call_value(["piece", 4, upper, low]),
                _canonical_call_value(low),
            )

    def test_indirect_call_effect_wrapper_is_transparent(self):
        value = ["parameter", 2, 4]
        iop = ["constant", 4, 0x123]
        self.assertEqual(_canonical_call_value(["indirect", 4, value, iop]), value)
        parameter = FakeVarnode(high=HighParam(2))
        sequence = FakeVarnode(value=0x123)
        wrapped = FakeVarnode(definition=FakeOp("INDIRECT", parameter, sequence))
        normalizer = ExpressionNormalizer(None, ImageId.ORIG, {}, {})
        self.assertEqual(
            _canonical_call_value(normalizer.normalize(wrapped)),
            ["parameter", 2, 4],
        )

    def test_nested_indirect_wrappers_dissolve(self):
        value = ["parameter", 5, 4]
        inner = ["indirect", 4, value, ["constant", 4, 0x10]]
        outer = ["indirect", 4, inner, ["constant", 4, 0x20]]
        self.assertEqual(_canonical_call_value(outer), value)

    def test_indirect_stripping_preserves_underlying_value_difference(self):
        left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [
                _canonical_call_value(
                    ["indirect", 4, ["parameter", 1, 4], ["constant", 4, 0x10]]
                )
            ],
        }
        right = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 2, 4]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    @staticmethod
    def _frame_call(*offsets: int, callee: str = "0x401000") -> dict:
        return {
            "kind": "direct",
            "target": {"function": callee},
            "arguments": [
                [
                    "int_add",
                    ["constant", offset % (1 << 32)],
                    ["register", "stack_pointer", 4],
                ]
                for offset in offsets
            ],
        }

    def test_frame_offset_shift_compares_equal_by_slot(self):
        original = [self._frame_call(-12)]
        recompiled = [self._frame_call(-16)]
        _normalize_frame_slots(original)
        _normalize_frame_slots(recompiled)
        result = compare_extracted_calls(
            ExtractedCalls(original, []), ExtractedCalls(recompiled, [])
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(original[0]["arguments"], [["local_slot", 0]])

    def test_distinct_locals_keep_distinct_slots(self):
        original = [self._frame_call(-24, -12)]
        recompiled = [self._frame_call(-28, -16)]
        _normalize_frame_slots(original)
        _normalize_frame_slots(recompiled)
        result = compare_extracted_calls(
            ExtractedCalls(original, []), ExtractedCalls(recompiled, [])
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            original[0]["arguments"], [["local_slot", 0], ["local_slot", 1]]
        )

    def test_swapped_locals_across_calls_still_mismatch(self):
        original = [
            self._frame_call(-24, callee="0x401000"),
            self._frame_call(-12, callee="0x402000"),
        ]
        recompiled = [
            self._frame_call(-12, callee="0x401000"),
            self._frame_call(-24, callee="0x402000"),
        ]
        _normalize_frame_slots(original)
        _normalize_frame_slots(recompiled)
        result = compare_extracted_calls(
            ExtractedCalls(original, []), ExtractedCalls(recompiled, [])
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    def test_positive_stack_offsets_stay_concrete(self):
        calls = [self._frame_call(8)]
        _normalize_frame_slots(calls)
        self.assertEqual(
            calls[0]["arguments"],
            [["int_add", ["constant", 8], ["register", "stack_pointer", 4]]],
        )

    def test_frame_slot_vs_nonframe_argument_still_mismatch(self):
        original = [self._frame_call(-12)]
        _normalize_frame_slots(original)
        recompiled = [
            {
                "kind": "direct",
                "target": {"function": "0x401000"},
                "arguments": [["constant", 0]],
            }
        ]
        _normalize_frame_slots(recompiled)
        result = compare_extracted_calls(
            ExtractedCalls(original, []), ExtractedCalls(recompiled, [])
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    @staticmethod
    def _call_site(program, ops, function_map):
        normalizer = ExpressionNormalizer(None, ImageId.ORIG, {}, {})
        return extract_calls(
            FakeHighFunction(ops), program, normalizer, function_map, {}
        )

    def test_eh_prolog_call_is_not_part_of_the_contract(self):
        class AddressedVarnode(FakeVarnode):
            def getAddress(self):
                return hex(self.value)

        program = FakeProgram(
            {
                0x5E9AE8: FakeFunction([], name="_EH_prolog", entry=0x5E9AE8),
                0x401000: FakeFunction([], name="DoWork", entry=0x401000),
            }
        )
        ops = [
            FakeOp("CALL", AddressedVarnode(value=0x5E9AE8)),
            FakeOp("CALL", AddressedVarnode(value=0x401000)),
        ]
        extracted = self._call_site(program, ops, {0x401000: 0x401000})
        self.assertEqual(len(extracted.calls), 1)
        self.assertEqual(extracted.calls[0]["target"], {"function": "0x401000"})
        self.assertEqual(extracted.unresolved, [])
        recompiled = ExtractedCalls(
            [{"kind": "direct", "target": {"function": "0x401000"}, "arguments": []}],
            [],
        )
        result = compare_extracted_calls(extracted, recompiled)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["original_call_count"], 1)

    def test_scaffolding_rule_never_covers_real_base_bodies(self):
        class AddressedVarnode(FakeVarnode):
            def getAddress(self):
                return hex(self.value)

        program = FakeProgram(
            {0x402000: FakeFunction([], name="CWnd::~CWnd", entry=0x402000)}
        )
        ops = [FakeOp("CALL", AddressedVarnode(value=0x402000))]
        extracted = self._call_site(program, ops, {0x402000: 0x402000})
        self.assertEqual(len(extracted.calls), 1)
        result = compare_extracted_calls(extracted, ExtractedCalls([], []))
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_count")

    def test_missing_real_call_still_fails_next_to_dropped_scaffolding(self):
        class AddressedVarnode(FakeVarnode):
            def getAddress(self):
                return hex(self.value)

        program = FakeProgram(
            {
                0x5E9AE8: FakeFunction([], name="_EH_prolog", entry=0x5E9AE8),
                0x401000: FakeFunction([], name="DoWork", entry=0x401000),
                0x402000: FakeFunction([], name="DoMore", entry=0x402000),
            }
        )
        ops = [
            FakeOp("CALL", AddressedVarnode(value=0x5E9AE8)),
            FakeOp("CALL", AddressedVarnode(value=0x401000)),
            FakeOp("CALL", AddressedVarnode(value=0x402000)),
        ]
        extracted = self._call_site(
            program, ops, {0x401000: 0x401000, 0x402000: 0x402000}
        )
        recompiled = ExtractedCalls(
            [{"kind": "direct", "target": {"function": "0x401000"}, "arguments": []}],
            [],
        )
        result = compare_extracted_calls(extracted, recompiled)
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_count")
        self.assertEqual(
            result["missing"],
            [
                {
                    "count": 1,
                    "call": {
                        "kind": "direct",
                        "target": {"function": "0x402000"},
                        "arguments": [],
                    },
                }
            ],
        )

    def test_virtual_dispatch_is_recognized_through_indirect_pointer(self):
        receiver = FakeVarnode(high=HighParam(0))
        wrapped_receiver = FakeVarnode(
            definition=FakeOp("INDIRECT", receiver, FakeVarnode(value=0x40))
        )
        vtable = FakeVarnode(definition=FakeOp("LOAD", wrapped_receiver))
        slot_pointer = FakeVarnode(
            definition=FakeOp("PTRSUB", vtable, FakeVarnode(value=8))
        )
        target = FakeVarnode(definition=FakeOp("LOAD", slot_pointer))
        resolved = _virtual_target(target)
        self.assertIsNotNone(resolved)
        found_receiver, slot = resolved
        self.assertIs(found_receiver, receiver)
        self.assertEqual(slot, 8)

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

    def test_declared_arity_disagreement_is_inconclusive_not_mismatch(self):
        left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 1]],
        }
        right = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 1], ["symbol", "unaff_retaddr", 4]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []),
            ExtractedCalls([right], []),
            frozenset({"0x401000"}),
        )
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "prototype_arity_asymmetry")

    def test_same_declared_arity_argument_change_still_fails(self):
        left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 1], ["parameter", 2]],
        }
        right = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 1], ["parameter", 3]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    def test_arity_relaxation_never_hides_target_or_multiplicity(self):
        left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["parameter", 1]],
        }
        right = {
            "kind": "direct",
            "target": {"function": "0x402000"},
            "arguments": [["parameter", 1], ["parameter", 2]],
        }
        flagged = frozenset({"0x401000", "0x402000"})
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], []), flagged
        )
        self.assertEqual(result["status"], "mismatch")
        count_result = compare_extracted_calls(
            ExtractedCalls([left, left], []), ExtractedCalls([left], []), flagged
        )
        self.assertEqual(count_result["status"], "mismatch")
        self.assertEqual(count_result["reason"], "call_count")

    def test_virtual_arity_prefix_downgrades_to_inconclusive(self):
        left = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["entity", 2, "0x6a20f8"]},
            "arguments": [],
        }
        right = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["entity", 2, "0x6a20f8"]},
            "arguments": [["parameter", 1]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "prototype_arity_asymmetry")

    def test_virtual_prefix_never_hides_receiver_or_argument_change(self):
        base = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["parameter", 0]},
            "arguments": [],
        }
        other_receiver = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["parameter", 1]},
            "arguments": [["parameter", 1]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([base], []), ExtractedCalls([other_receiver], [])
        )
        self.assertEqual(result["status"], "mismatch")
        changed_shared_position = {
            "kind": "virtual",
            "target": {"slot": 132, "receiver": ["parameter", 0]},
            "arguments": [["parameter", 2], ["parameter", 3]],
        }
        with_args = dict(base, arguments=[["parameter", 1]])
        result = compare_extracted_calls(
            ExtractedCalls([with_args], []),
            ExtractedCalls([changed_shared_position], []),
        )
        self.assertEqual(result["status"], "mismatch")

    def test_nested_asymmetric_call_result_is_erased_everywhere(self):
        def outer(inner_arguments):
            inner = ["call_result", {"function": "0x5798a0"}, inner_arguments]
            return {
                "kind": "virtual",
                "target": {"slot": 452, "receiver": inner},
                "arguments": [inner, ["constant", 0]],
            }

        left = outer([["parameter", 1]])
        right = outer([["call_result", {"function": "0x5798a0"}, []], ["parameter", 1]])
        flagged = frozenset({"0x5798a0"})
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], []), flagged
        )
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "prototype_arity_asymmetry")
        unflagged = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(unflagged["status"], "mismatch")

    def test_entry_ecx_is_the_thiscall_receiver(self):
        ecx = FakeVarnode(register=True)
        normalizer = ExpressionNormalizer(
            FakeProgram(None, register_name="ECX"), ImageId.ORIG, {}, {}
        )
        self.assertEqual(normalizer.normalize(ecx), ["parameter", 0, 4])
        other = FakeVarnode(register=True)
        edx_normalizer = ExpressionNormalizer(
            FakeProgram(None, register_name="EDX"), ImageId.ORIG, {}, {}
        )
        self.assertEqual(edx_normalizer.normalize(other), ["register", "edx", 4])

    def test_local_variable_model_diff_is_inconclusive_not_mismatch(self):
        left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["symbol", "iStack_c", 4]],
        }
        right = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [
                ["int_sub", ["symbol", "iStack_8", 4], ["parameter", 1]]
            ],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "local_variable_model")

    def test_unbound_stack_input_vs_parameter_is_inconclusive(self):
        left = {
            "kind": "direct",
            "target": {"external": {"library": "USER32.DLL", "symbol": "CopyRect"}},
            "arguments": [["local_slot", 0], ["symbol", "in_stack_00000008", 4]],
        }
        right = {
            "kind": "direct",
            "target": {"external": {"library": "USER32.DLL", "symbol": "CopyRect"}},
            "arguments": [["local_slot", 0], ["parameter", 1]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([left], []), ExtractedCalls([right], [])
        )
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "local_variable_model")

    def test_local_variable_downgrade_needs_stack_symbols_in_every_diff(self):
        stack_left = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["symbol", "iStack_c", 4]],
        }
        stack_right = {
            "kind": "direct",
            "target": {"function": "0x401000"},
            "arguments": [["symbol", "uStack_10", 4]],
        }
        plain_left = {
            "kind": "direct",
            "target": {"function": "0x402000"},
            "arguments": [["parameter", 1]],
        }
        plain_right = {
            "kind": "direct",
            "target": {"function": "0x402000"},
            "arguments": [["parameter", 2]],
        }
        result = compare_extracted_calls(
            ExtractedCalls([stack_left, plain_left], []),
            ExtractedCalls([stack_right, plain_right], []),
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    def test_asymmetric_arity_target_set_is_this_adjusted(self):
        original = {
            0x401000: DirectCallABI(parameter_count=2, has_this=True, has_varargs=False),
            0x402000: DirectCallABI(parameter_count=1, has_this=False, has_varargs=False),
            0x403000: DirectCallABI(parameter_count=1, has_this=False, has_varargs=False),
            0x404000: DirectCallABI(parameter_count=0, has_this=False, has_varargs=False),
        }
        recompiled = {
            0x401000: DirectCallABI(parameter_count=1, has_this=False, has_varargs=False),
            0x402000: DirectCallABI(parameter_count=2, has_this=False, has_varargs=False),
            0x403000: DirectCallABI(parameter_count=1, has_this=False, has_varargs=True),
        }
        flagged = _asymmetric_arity_targets(original, recompiled)
        self.assertNotIn("0x401000", flagged)  # this-adjusted arities agree
        self.assertIn("0x402000", flagged)
        self.assertIn("0x403000", flagged)  # varargs disagreement
        self.assertNotIn("0x404000", flagged)  # absent from recomp map

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

    def test_varargs_arity_asymmetry_is_inconclusive_not_mismatch(self):
        # Same call, but only one image's decompiler attached the pushed values.
        target = {"function": "0x49d620"}
        original = ExtractedCalls(
            calls=[
                {
                    "kind": "direct",
                    "target": target,
                    "arguments": [["constant", 4, 6898320], ["constant", 4, 950]],
                    "varargs_target": True,
                }
            ],
            unresolved=[],
        )
        recompiled = ExtractedCalls(
            calls=[
                {
                    "kind": "direct",
                    "target": target,
                    "arguments": [],
                    "varargs_target": True,
                }
            ],
            unresolved=[],
        )
        result = compare_extracted_calls(original, recompiled)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "prototype_arity_asymmetry")

    def test_varargs_relaxation_never_hides_a_different_target(self):
        left = ExtractedCalls(
            calls=[
                {
                    "kind": "direct",
                    "target": {"function": "0x49d620"},
                    "arguments": [],
                    "varargs_target": True,
                }
            ],
            unresolved=[],
        )
        right = ExtractedCalls(
            calls=[
                {
                    "kind": "direct",
                    "target": {"function": "0x401000"},
                    "arguments": [],
                    "varargs_target": True,
                }
            ],
            unresolved=[],
        )
        result = compare_extracted_calls(left, right)
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    def test_varargs_relaxation_never_hides_a_non_varargs_argument_change(self):
        varargs_call = {
            "kind": "direct",
            "target": {"function": "0x49d620"},
            "arguments": [],
            "varargs_target": True,
        }
        def plain(value):
            return {
                "kind": "direct",
                "target": {"function": "0x401000"},
                "arguments": [["constant", 4, value]],
            }
        left = ExtractedCalls(calls=[varargs_call, plain(1)], unresolved=[])
        right = ExtractedCalls(calls=[varargs_call, plain(2)], unresolved=[])
        result = compare_extracted_calls(left, right)
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_contract")

    def test_varargs_relaxation_never_hides_a_call_count_change(self):
        call = {
            "kind": "direct",
            "target": {"function": "0x49d620"},
            "arguments": [],
            "varargs_target": True,
        }
        result = compare_extracted_calls(
            ExtractedCalls(calls=[call, call], unresolved=[]),
            ExtractedCalls(calls=[call], unresolved=[]),
        )
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(result["reason"], "call_count")

    def test_pointer_constant_is_mapped_to_its_entity(self):
        class EmptyProgram:
            def getMemory(self):
                class Bound:
                    def __init__(self, value):
                        self.value = value

                    def getOffset(self):
                        return self.value

                class Memory:
                    def getMinAddress(self):
                        return Bound(0x400000)

                    def getMaxAddress(self):
                        return Bound(0x700000)

                return Memory()

        normalizer = ExpressionNormalizer(
            EmptyProgram(), ImageId.RECOMP, {0x5A0000: (3, 0x690000)}, {}
        )
        # A string/global pointer passed as an immediate resolves to the entity,
        # so the two images compare equal despite different absolute addresses.
        self.assertEqual(
            normalizer.normalize(FakeVarnode(value=0x5A0000)),
            ["entity", 3, "0x690000", 4],
        )
        # A plain integer argument keeps its numeric identity.
        self.assertEqual(
            normalizer.normalize(FakeVarnode(value=48)), ["constant", 4, 48]
        )

    def test_report_diff_flags_status_reason_and_membership_changes(self):
        previous = {
            "functions": [
                {"original": "0x1", "status": "pass", "reason": "call_contract_equal"},
                {"original": "0x2", "status": "mismatch", "reason": "call_count"},
                {"original": "0x3", "status": "pass", "reason": "reccmp_proven"},
            ]
        }
        current = {
            "functions": [
                {"original": "0x1", "status": "pass", "reason": "call_contract_equal"},
                {"original": "0x2", "status": "pass", "reason": "call_contract_equal"},
                {"original": "0x4", "status": "pass", "reason": "reccmp_proven"},
            ]
        }
        diffs = _diff_reports(previous, current)
        self.assertEqual(len(diffs), 3)
        self.assertTrue(any(item.startswith("0x3: removed") for item in diffs))
        self.assertTrue(any(item.startswith("0x4: added") for item in diffs))
        self.assertTrue(
            any("status: mismatch -> pass" in item for item in diffs)
        )
        self.assertEqual(_diff_reports(previous, previous), [])

    def test_stale_cache_pruning_keeps_current_and_newest_previous(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "ghidra-semantic"
            log_dir = Path(raw) / "semantic"
            log_dir.mkdir()
            names = ["aaa", "bbb", "ccc", "ddd"]
            for age, name in enumerate(reversed(names)):
                directory = root / name
                directory.mkdir(parents=True)
                stamp = time.time() - age * 100
                os.utime(directory, (stamp, stamp))
                (log_dir / f"cache-{name}.log").write_text("log")
            _prune_stale_caches(root, "ddd")
            survivors = sorted(entry.name for entry in root.iterdir() if entry.is_dir())
            self.assertEqual(len(survivors), CACHE_KEEP_COUNT)
            self.assertIn("ddd", survivors)
            self.assertIn("ccc", survivors)  # newest besides current
            self.assertFalse((log_dir / "cache-aaa.log").exists())
            self.assertTrue((log_dir / "cache-ddd.log").exists())

    def test_stale_cache_pruning_protects_current_even_when_old(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "ghidra-semantic"
            (Path(raw) / "semantic").mkdir()
            for age, name in enumerate(["new1", "new2", "current"]):
                directory = root / name
                directory.mkdir(parents=True)
                stamp = time.time() - age * 100
                os.utime(directory, (stamp, stamp))
            _prune_stale_caches(root, "current")
            survivors = {entry.name for entry in root.iterdir() if entry.is_dir()}
            self.assertIn("current", survivors)
            self.assertEqual(len(survivors), CACHE_KEEP_COUNT)

    def _reuse_context(self, image: dict[int, bytes] | None = None) -> ReuseContext:
        blobs = image if image is not None else {0x2000: b"\x55\x8b\xec" * 40}

        def read(vaddr: int, size: int) -> bytes | None:
            blob = blobs.get(vaddr)
            if blob is None or len(blob) < size:
                return None
            return blob[:size]

        return ReuseContext(
            pairs={0x1000: FunctionPair(0x1000, 0x2000)},
            original_functions={0x1000: 0x1000},
            recompiled_functions={0x2000: 0x1000},
            original_entities={0x9000: (3, 0x9000)},
            recompiled_entities={0xA000: (3, 0x9000)},
            identities={0x1000: "id-caller"},
            sizes={0x1000: 120},
            read=read,
        )

    def test_normalizer_records_entity_map_and_miss_deps(self):
        class EmptyProgram:
            pass

        recorder = DepRecorder()
        normalizer = ExpressionNormalizer(
            EmptyProgram(), ImageId.RECOMP, {0xA000: (3, 0x9000)}, {0x2000: 0x1000}
        )
        normalizer.recorder = recorder
        self.assertEqual(
            normalizer.normalize(FakeVarnode(value=0xA000, address=True)),
            ["entity", 3, "0x9000", 4],
        )
        self.assertEqual(
            normalizer.normalize(FakeVarnode(value=0x2000, address=True)),
            ["function", "0x1000"],
        )
        self.assertIn(("entity", "recomp", 0xA000, 3, 0x9000), recorder.events)
        self.assertIn(("map_fn", "recomp", 0x2000, 0x1000), recorder.events)
        self.assertFalse(recorder.fragile)

    def test_dep_encode_and_match_round_trip(self):
        ctx = self._reuse_context()
        events = [
            ("entity", "recomp", 0xA000, 3, 0x9000),
            ("map_fn", "orig", 0x1000, 0x1000),
            ("miss", "recomp", 0x7777),
            ("fn_pair", 0x1000),
            ("pairs_fp",),
            ("nonmem", "recomp", 0x8888),
        ]
        for event in events:
            dep = _encode_dep(event, ctx)
            self.assertIsNotNone(dep, event)
            self.assertTrue(_dep_matches(dep, ctx), dep)
        stale_entity = _encode_dep(("entity", "recomp", 0xA000, 3, 0x9000), ctx)
        ctx.recompiled_entities[0xA000] = (4, 0x9000)
        self.assertFalse(_dep_matches(stale_entity, ctx))
        newly_mapped = _encode_dep(("miss", "recomp", 0x7777), ctx)
        ctx.recompiled_functions[0x7777] = 0x1234
        self.assertFalse(_dep_matches(newly_mapped, ctx))

    def test_row_reuse_requires_identical_function_bytes(self):
        ctx = self._reuse_context()
        rows = [
            {
                "original": "0x1000",
                "status": "pass",
                "reason": "call_contract_equal",
                "_recorder": DepRecorder(),
            }
        ]
        _attach_reuse_records(rows, ctx)
        row = rows[0]
        self.assertIn("reuse", row)
        self.assertTrue(_row_reusable(row, ctx))
        changed = self._reuse_context(image={0x2000: b"\x90" * 120})
        self.assertFalse(_row_reusable(row, changed))
        renamed = self._reuse_context()
        renamed.identities[0x1000] = "id-renamed"
        self.assertFalse(_row_reusable(row, renamed))

    def test_fragile_rows_never_get_reuse_records(self):
        ctx = self._reuse_context()
        fragile = DepRecorder()
        fragile.mark_fragile()
        rows = [
            {"original": "0x1000", "status": "pass", "_recorder": fragile},
            {
                "original": "0x1000",
                "status": "inconclusive",
                "reason": "decompilation",
                "_recorder": DepRecorder(),
            },
            {"original": "0x1000", "status": "pass"},
        ]
        _attach_reuse_records(rows, ctx)
        for row in rows:
            self.assertNotIn("reuse", row)
            self.assertNotIn("_recorder", row)

    def test_unpaired_target_rows_depend_on_the_pairing_set(self):
        ctx = self._reuse_context()
        recorder = DepRecorder()
        recorder.pairs_dep()
        rows = [
            {
                "original": "0x1000",
                "status": "inconclusive",
                "reason": "unresolved_call_contract",
                "_recorder": recorder,
            }
        ]
        _attach_reuse_records(rows, ctx)
        self.assertTrue(_row_reusable(rows[0], ctx))
        grown = self._reuse_context()
        grown.pairs[0x5000] = FunctionPair(0x5000, 0x6000)
        grown.pairs_fp = ReuseContext(
            pairs=grown.pairs,
            original_functions={},
            recompiled_functions={},
            original_entities={},
            recompiled_entities={},
            identities=grown.identities,
            sizes=grown.sizes,
            read=lambda vaddr, size: None,
        ).pairs_fp
        self.assertFalse(_row_reusable(rows[0], grown))

    def test_orig_calls_cache_round_trips_calls_and_deps(self):
        recorder = DepRecorder()
        recorder.entity(ImageId.ORIG, 0x500000, 3, 0x600000)
        recorder.fn_pair(0x401000)
        recorder.pairs_dep()
        recorder.mark_fragile()
        extracted = ExtractedCalls(
            calls=[
                {
                    "kind": "direct",
                    "target": {"function": "0x401000"},
                    "arguments": [["parameter", 1]],
                }
            ],
            unresolved=["0x5: oops"],
        )
        entry = json.loads(json.dumps(_orig_calls_entry(extracted, recorder)))
        replay = DepRecorder()
        restored = _restore_orig_calls(entry, replay)
        self.assertEqual(restored.calls, extracted.calls)
        self.assertEqual(restored.unresolved, extracted.unresolved)
        self.assertEqual(replay.events, recorder.events)
        self.assertTrue(replay.fragile)

    def test_orig_calls_cache_rejects_wrong_key_and_corrupt_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "orig_calls_cache.json"
            path.write_text(
                json.dumps({"key": "k1", "rows": {"0x1": {"calls": []}}}),
                encoding="utf-8",
            )
            self.assertEqual(
                _load_orig_calls_cache(path, "k1"), {"0x1": {"calls": []}}
            )
            self.assertEqual(_load_orig_calls_cache(path, "k2"), {})
            path.write_text("not json", encoding="utf-8")
            self.assertEqual(_load_orig_calls_cache(path, "k1"), {})
            self.assertEqual(_load_orig_calls_cache(Path(tmp) / "gone.json", "k1"), {})

    def test_audit_mode_uses_a_separate_report_file(self):
        previous = os.environ.pop("SEMANTIC_AUDIT_PRECISION", None)
        try:
            self.assertEqual(
                _full_report_relative_path(), REPORT_RELATIVE_PATH
            )
            os.environ["SEMANTIC_AUDIT_PRECISION"] = "1"
            self.assertEqual(
                _full_report_relative_path(), AUDIT_REPORT_RELATIVE_PATH
            )
        finally:
            if previous is None:
                os.environ.pop("SEMANTIC_AUDIT_PRECISION", None)
            else:
                os.environ["SEMANTIC_AUDIT_PRECISION"] = previous

    def test_targeted_report_pruning_is_age_based(self):
        with tempfile.TemporaryDirectory() as raw:
            semantic_dir = Path(raw)
            fresh = semantic_dir / "semantic_report.targeted-abc.json"
            stale = semantic_dir / "semantic_report.targeted-old.json"
            full = semantic_dir / "semantic_report.json"
            for path in (fresh, stale, full):
                path.write_text("{}")
            old = time.time() - 8 * 24 * 3600
            os.utime(stale, (old, old))
            os.utime(full, (old, old))
            _prune_targeted_reports(semantic_dir)
            self.assertTrue(fresh.exists())
            self.assertFalse(stale.exists())
            self.assertTrue(full.exists())  # never prune the full report


if __name__ == "__main__":
    unittest.main()
