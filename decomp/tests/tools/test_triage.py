"""Structured reccmp diagnosis rendering for `just triage`."""

from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from tools.reccmp.triage import _load_report, main, render_entity

DATA_RANGES = [(0x63E000, 0x6A0000)]
SYMBOLS = {0x4B2570: "TCity::InitializeCityProductionState"}
OWNERSHIP = {0x4B2570: "manual"}


def side(index=2, address=0x401020, **facts):
    return {"instruction_index": index, "address": address, "facts": facts}


def entity(
    status: str,
    *,
    difference=None,
    reasons=None,
    inconclusive=None,
    semantic_similarity=None,
):
    return {
        "address": "0x401000",
        "name": "TExample::Run",
        "matching": 1.0 if status == "exact" else 0.4286,
        "comparison": {
            "status": status,
            "effective_reasons": reasons or [],
            "difference": difference,
            "inconclusive_reason": inconclusive,
            "inconclusive_location": None,
            "semantic_similarity": semantic_similarity,
        },
        # Deliberately misleading rendered text. Triage must never inspect it.
        "diff": [["@@", [{"orig": [["0x0", "call Wrong"]]}]]],
    }


def mismatch(kind: str, orig, recomp):
    return entity("mismatch", difference={"kind": kind, "orig": orig, "recomp": recomp})


def render(value):
    return render_entity(value, DATA_RANGES, SYMBOLS, OWNERSHIP)


class TriageRenderTests(unittest.TestCase):
    def test_exact_output(self) -> None:
        self.assertEqual(
            render(entity("exact")),
            "0x00401000  100.00%  TExample::Run\n\n" "exact match — nothing to triage",
        )

    def test_effective_one_and_several_reasons(self) -> None:
        one = render(entity("effective", reasons=["register_allocation"]))
        self.assertIn("42.86% raw", one)
        self.assertIn("safe to ignore:\n  register allocation", one)
        several = render(
            entity(
                "effective",
                reasons=["register_allocation", "commutative_order", "padding"],
            )
        )
        self.assertIn(
            "register allocation\n  commutative operand order\n  alignment padding",
            several,
        )
        self.assertTrue(several.endswith("no action needed"))

    def test_memory_address_refined_to_field_offset(self) -> None:
        output = render(
            mismatch(
                "memory_address",
                side(
                    base_register="esi",
                    index_register=None,
                    scale=1,
                    displacement=0x98,
                    symbol=None,
                ),
                side(
                    address=0x501020,
                    base_register="esi",
                    index_register=None,
                    scale=1,
                    displacement=0x9C,
                    symbol=None,
                ),
            )
        )
        self.assertIn("original:   [esi + 0x98]", output)
        self.assertIn("recompiled: [esi + 0x9c]", output)
        self.assertIn("same object base, different member displacement", output)
        self.assertIn("ASSERT_SIZE", output)

    def test_mismatch_shows_diagnostic_and_raw_similarity(self) -> None:
        value = mismatch(
            "memory_value",
            side(value="imm:1"),
            side(address=0x501020, value="imm:2"),
        )
        value["comparison"]["semantic_similarity"] = 0.875
        output = render(value)
        self.assertIn("87.50% semantic similarity", output)
        self.assertIn("diagnostic; 42.86% raw", output)
        self.assertIn("first actionable mismatch", output)

    def test_memory_address_refined_to_stack_layout(self) -> None:
        output = render(
            mismatch(
                "memory_address",
                side(
                    base_register="ebp",
                    index_register=None,
                    scale=1,
                    displacement=-4,
                    symbol=None,
                ),
                side(
                    base_register="ebp",
                    index_register=None,
                    scale=1,
                    displacement=-8,
                    symbol=None,
                ),
            )
        )
        self.assertIn("stack-frame location differs", output)
        self.assertIn("next: just stackcmp 0x00401000", output)

    def test_implicit_store_address_uses_symbolic_value(self) -> None:
        output = render(
            mismatch(
                "memory_address",
                side(value="add:initial:sp,imm#2e8c2706"),
                side(address=0x501020, value="add:initial:sp,imm#59be4243"),
            )
        )
        self.assertIn("original:   [add:initial:sp,imm#2e8c2706]", output)
        self.assertIn("recompiled: [add:initial:sp,imm#59be4243]", output)
        self.assertIn("address/data-flow differs", output)

    def test_call_target_enriched_with_symbol_and_ownership(self) -> None:
        output = render(
            mismatch(
                "call_target",
                side(target=0x4B2570, target_name=None, target_instruction_index=None),
                side(
                    target=0x420000,
                    target_name="TView::Update",
                    target_instruction_index=None,
                ),
            )
        )
        self.assertIn("TCity::InitializeCityProductionState [manual]", output)
        self.assertIn("TView::Update", output)
        self.assertIn("original callee source owner: manual", output)

    def test_ecx_call_argument_is_receiver_mismatch(self) -> None:
        output = render(
            mismatch(
                "call_argument",
                side(register="ecx", value="load:g_pMainView"),
                side(register="ecx", value="load:g_pTitleView"),
            )
        )
        self.assertIn("likely receiver mismatch", output)
        self.assertIn("load:g_pMainView", output)

    def test_symbol_resolution_advice(self) -> None:
        output = render(
            mismatch(
                "symbol_resolution",
                side(symbol="<OFFSET1>"),
                side(symbol="g_apNationStates"),
            )
        )
        self.assertIn("original_entities.csv", output)
        self.assertIn("GLOBAL/STRING/FUNCTION annotation", output)

    def test_immediate_in_and_out_of_data_ranges(self) -> None:
        in_data = render(
            mismatch("immediate_value", side(value=0x63F000), side(value=16))
        )
        self.assertIn("lies in a data section", in_data)
        scalar = render(mismatch("immediate_value", side(value=4), side(value=5)))
        self.assertIn("scalar constant, enum, flag", scalar)

    def test_other_machine_state_messages(self) -> None:
        cases = {
            "branch_condition": (
                side(predicate="eq:a:b"),
                side(predicate="ne:a:b"),
                "branch predicate differs",
            ),
            "branch_target": (
                side(target_instruction_index=3),
                side(target_instruction_index=4),
                "canonical successor differs",
            ),
            "return_value": (
                side(value="imm:1"),
                side(value="imm:2"),
                "typed return state differs",
            ),
            "preserved_state": (
                side(value="init:ebx"),
                side(value="imm:0"),
                "callee-saved register or stack state differs",
            ),
        }
        for kind, (orig, recomp, expected) in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(expected, render(mismatch(kind, orig, recomp)))

    def test_inconclusive_output_with_location(self) -> None:
        value = entity("inconclusive", inconclusive="unsupported_control_flow")
        value["comparison"]["inconclusive_location"] = side(index=7, address=0x401278)
        output = render(value)
        self.assertIn("unsupported control flow at original 0x00401278", output)
        self.assertTrue(
            output.endswith("Investigate verifier/metadata/alignment instead.")
        )

    def test_inconclusive_cfg_diagnostic_renders_structured_facts_and_advice(self) -> None:
        value = entity("inconclusive", inconclusive="non_isomorphic_cfg")
        value["comparison"]["inconclusive_location"] = side(
            index=7,
            address=0x401278,
            failure="edge_roles",
            orig_block_count=8,
            recomp_block_count=9,
            orig_edge_roles="fall,taken",
            recomp_edge_roles="jmp",
        )
        output = render(value)
        self.assertIn("non isomorphic cfg at original 0x00401278", output)
        self.assertIn("failure: edge_roles", output)
        self.assertIn("orig block count: 8", output)
        self.assertIn("recomp edge roles: jmp", output)
        self.assertIn("reachable block graphs differ", output)
        self.assertIn("semantic span scoring cannot start", output)

    def test_rendering_is_deterministic(self) -> None:
        value = entity(
            "effective",
            reasons=["register_allocation", "commutative_order"],
        )
        self.assertEqual(render(value), render(value))


class TriageReportTests(unittest.TestCase):
    def test_report_json_requires_only_new_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = {"format": 1, "data": [entity("exact")]}
            path.write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(_load_report(path), report["data"])
            report["data"][0].pop("comparison")
            report["data"][0]["effective"] = True
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "structured comparison"):
                _load_report(path)

    @patch("tools.reccmp.triage.ownership_by_address", return_value={})
    @patch("tools.reccmp.triage.names_by_address", return_value={})
    @patch("tools.reccmp.triage.PeImage")
    @patch("tools.reccmp.triage.original_exe_from_user_yml")
    @patch("tools.reccmp.triage.run_report", return_value=[entity("exact")])
    def test_live_report_path_consumes_structured_result(
        self, run_report_mock, original_exe_mock, pe_image_mock, *_unused
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "imperialism.exe"
            exe.write_bytes(b"MZ")
            original_exe_mock.return_value = exe
            pe_image_mock.return_value.data_ranges.return_value = []
            with patch("sys.argv", ["triage", "0x401000"]):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), 0)
            run_report_mock.assert_called_once()
            self.assertEqual(run_report_mock.call_args.kwargs["diet"], True)
            self.assertEqual(
                run_report_mock.call_args.kwargs["orig_addresses"], [0x401000]
            )


if __name__ == "__main__":
    unittest.main()
