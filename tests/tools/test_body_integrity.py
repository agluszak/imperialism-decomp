#!/usr/bin/env python3
"""Body-integrity audit: the pure analysis layer, driven by real-world shapes.

The Ghidra collector needs a live DB, but every judgement lives in `analyze`, so the
fixtures here are FunctionViews describing bodies that actually occurred:
imperialism-decomp-6q2 (inner pseudo-function demoted to a label, bytes never returned)
and imperialism-decomp-ffaj (assert call split across a fabricated function boundary).
"""

from __future__ import annotations

import unittest

from tools.ghidra.body_integrity import (
    ALL_KINDS,
    FunctionView,
    Report,
    analyze,
    audit,
    body_holes,
    body_size,
    format_report,
)


def kinds(function: FunctionView) -> set[str]:
    return {violation.kind for violation in analyze(function)}


class BodyHoleGeometryTests(unittest.TestCase):
    def test_contiguous_body_has_no_holes(self):
        self.assertEqual(body_holes(((0x1000, 0x10FF),)), [])
        self.assertEqual(body_size(((0x1000, 0x10FF),)), 256)

    def test_adjacent_ranges_are_not_a_hole(self):
        self.assertEqual(body_holes(((0x1000, 0x10FF), (0x1100, 0x11FF))), [])

    def test_gap_between_ranges_is_reported_inclusively(self):
        self.assertEqual(body_holes(((0x1000, 0x10FF), (0x1140, 0x11FF))), [(0x1100, 0x113F)])
        self.assertEqual(body_size(((0x1000, 0x10FF), (0x1140, 0x11FF))), 256 + 192)

    def test_ranges_are_ordered_before_comparison(self):
        self.assertEqual(body_holes(((0x1140, 0x11FF), (0x1000, 0x10FF))), [(0x1100, 0x113F)])


class PuncturedBodyTests(unittest.TestCase):
    """The bd 6q2 shape: demoted inner function, code left owned by nobody."""

    PUNCTURED = FunctionView(
        entry=0x004C8AC0,
        name="TShipyardView::DoEvent",
        ranges=((0x004C8AC0, 0x004C8C08), (0x004C8C40, 0x004C8CD2)),
        last_mnemonic="RET",
        boundary_mnemonic=None,
        labels=(0x004C8C09,),
    )

    def test_hole_and_its_label_are_both_hard_violations(self):
        found = {v.kind: v for v in analyze(self.PUNCTURED)}
        self.assertIn("body_hole", found)
        self.assertIn("label_in_hole", found)
        self.assertTrue(found["body_hole"].hard)
        self.assertTrue(found["label_in_hole"].hard)
        self.assertIn("0x004c8c09-0x004c8c3f", found["body_hole"].detail)
        self.assertIn("55 bytes", found["body_hole"].detail)

    def test_hole_without_a_label_reports_only_the_hole(self):
        view = FunctionView(
            entry=self.PUNCTURED.entry,
            name=self.PUNCTURED.name,
            ranges=self.PUNCTURED.ranges,
            last_mnemonic="RET",
        )
        self.assertEqual(kinds(view), {"body_hole"})

    def test_clean_body_reports_nothing(self):
        view = FunctionView(
            entry=0x004C8AC0,
            name="TShipyardView::DoEvent",
            ranges=((0x004C8AC0, 0x004C8CD2),),
            last_mnemonic="RET",
            boundary_mnemonic="PUSH",
            boundary_owner=0x004C8CD3,
            curated_size=0x213,
        )
        self.assertEqual(analyze(view), [])


class TruncatedBodyTests(unittest.TestCase):
    """The bd ffaj shape: a body cut between the two pushes of one call."""

    def test_fallthrough_into_unowned_code_is_hard(self):
        view = FunctionView(
            entry=0x004C8AC0,
            name="TShipyardView::DoEvent",
            ranges=((0x004C8AC0, 0x004C8C08),),
            last_mnemonic="PUSH",
            boundary_mnemonic="PUSH",
            boundary_owner=None,
        )
        self.assertEqual(kinds(view), {"fallthrough_to_unowned"})
        self.assertTrue(analyze(view)[0].hard)

    def test_fallthrough_into_a_foreign_function_is_hard(self):
        view = FunctionView(
            entry=0x004C8AC0,
            name="TShipyardView::DoEvent",
            ranges=((0x004C8AC0, 0x004C8C08),),
            last_mnemonic="PUSH",
            boundary_mnemonic="PUSH",
            boundary_owner=0x004C8C09,
        )
        found = analyze(view)
        self.assertEqual([v.kind for v in found], ["truncated_into_function"])
        self.assertIn("0x004c8c09", found[0].detail)

    def test_terminator_ending_is_never_a_fallthrough(self):
        for mnemonic in ("RET", "JMP", "INT3", "ret"):
            view = FunctionView(
                entry=0x1000,
                name="fn",
                ranges=((0x1000, 0x10FF),),
                last_mnemonic=mnemonic,
                boundary_mnemonic="PUSH",
                boundary_owner=None,
            )
            self.assertEqual(kinds(view), set(), mnemonic)

    def test_undisassembled_boundary_is_not_a_violation(self):
        view = FunctionView(
            entry=0x1000,
            name="fn",
            ranges=((0x1000, 0x10FF),),
            last_mnemonic="PUSH",
            boundary_mnemonic=None,
        )
        self.assertEqual(kinds(view), set())


class AdvisoryTests(unittest.TestCase):
    def test_inner_entry_and_size_mismatch_are_advisory(self):
        view = FunctionView(
            entry=0x1000,
            name="fn",
            ranges=((0x1000, 0x10FF),),
            last_mnemonic="RET",
            inner_entries=(0x1040,),
            curated_size=512,
        )
        found = {v.kind: v for v in analyze(view)}
        self.assertEqual(set(found), {"contains_other_entry", "curated_size_mismatch"})
        self.assertFalse(any(v.hard for v in found.values()))
        self.assertIn("inventory says 512 bytes, DB body is 256", found["curated_size_mismatch"].detail)

    def test_matching_curated_size_is_silent(self):
        view = FunctionView(
            entry=0x1000, name="fn", ranges=((0x1000, 0x10FF),),
            last_mnemonic="RET", curated_size=256,
        )
        self.assertEqual(analyze(view), [])


class ReportTests(unittest.TestCase):
    def test_audit_separates_hard_violations_for_strict_mode(self):
        punctured = PuncturedBodyTests.PUNCTURED
        advisory = FunctionView(
            entry=0x2000, name="other", ranges=((0x2000, 0x20FF),),
            last_mnemonic="RET", curated_size=999,
        )
        report = audit([punctured, advisory])
        self.assertEqual(report.checked, 2)
        self.assertEqual({v.kind for v in report.hard}, {"body_hole", "label_in_hole"})
        self.assertLess(len(report.hard), len(report.violations))

    def test_clean_audit_has_no_hard_violations(self):
        self.assertEqual(audit([]).hard, [])
        self.assertEqual(audit([]).violations, [])

    def test_format_lists_hard_violations_first_and_counts_every_kind(self):
        text = format_report(audit([PuncturedBodyTests.PUNCTURED]))
        self.assertIn("functions checked: 1", text)
        for kind in ALL_KINDS:
            self.assertIn(f"{kind}=", text)
        self.assertLess(text.index("[HARD]"), len(text))

    def test_kind_filter_selects_one_class(self):
        text = format_report(audit([PuncturedBodyTests.PUNCTURED]), kind="label_in_hole")
        self.assertIn("label_in_hole 0x004c8ac0", text)
        self.assertNotIn("[HARD] body_hole", text)

    def test_limit_truncates_and_says_so(self):
        text = format_report(audit([PuncturedBodyTests.PUNCTURED]), limit=1)
        self.assertIn("more (raise --limit)", text)

    def test_empty_report_renders(self):
        self.assertIn("violations: 0", format_report(Report(checked=7)))


if __name__ == "__main__":
    unittest.main()
