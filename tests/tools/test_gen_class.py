#!/usr/bin/env python3
"""Tests for tools.workflow.gen_class (marked-region render + idempotent upsert)."""

from __future__ import annotations

import unittest

from tools.workflow.gen_class import (
    _classified_from_manifest,
    find_block,
    render_generated_block,
    upsert_block,
)


def _manifest(size_verified: bool = False) -> dict:
    curated_layout = {"base_offset": "0x04", "status": "recovered"}
    if size_verified:
        curated_layout["size_verified"] = True
    return {
        "class": "TFoo",
        "generated": {
            "vtable_addr": "0x00650000",
            "object_size": "0x40",
            "base": "TObject",
            "ancestry": ["TFoo", "TObject"],
            "root": "TObject",
            "slots": [
                {"index": "0x00", "byte": "0x00", "target": "0x004b0000", "kind": "new", "ghidra_name": "TFoo::GetClass"},
                {"index": "0x05", "byte": "0x14", "target": "0x004b0100", "kind": "override", "ghidra_name": "TFoo::WriteTo"},
            ],
        },
        "curated": {
            "layout": curated_layout,
            "slots": [{"index": "0x05", "method": "WriteToStream", "confidence": "high"}],
        },
    }


class RenderBlockTests(unittest.TestCase):
    def test_block_has_no_vtable_marker(self) -> None:
        block = render_generated_block(_manifest())
        # A `// VTABLE:` keyword would be stolen by the VTABLE-annotation gate.
        self.assertNotIn("VTABLE:", block)
        self.assertIn("vtable @ 0x00650000", block)

    def test_curated_method_wins_over_ghidra_name(self) -> None:
        block = render_generated_block(_manifest())
        self.assertIn("WriteToStream", block)  # curated
        self.assertIn("GetClass", block)  # ghidra fallback for the uncurated slot

    def test_static_assert_commented_unless_verified(self) -> None:
        unverified = render_generated_block(_manifest(size_verified=False))
        # The assert text appears but only inside a comment line.
        for line in unverified.splitlines():
            if "static_assert" in line:
                self.assertTrue(line.lstrip().startswith("//"))
        verified = render_generated_block(_manifest(size_verified=True))
        self.assertIn("\nstatic_assert(sizeof(TFoo) == 0x40", verified)


class UpsertBlockTests(unittest.TestCase):
    def test_append_then_idempotent(self) -> None:
        header = "#pragma once\nclass TFoo {};\n"
        block = render_generated_block(_manifest())
        out1, changed1 = upsert_block(header, "TFoo", block)
        self.assertTrue(changed1)
        self.assertIn("BEGIN GENERATED (TFoo)", out1)
        # Hand content preserved
        self.assertIn("class TFoo {};", out1)
        # Re-running is a no-op
        out2, changed2 = upsert_block(out1, "TFoo", block)
        self.assertFalse(changed2)
        self.assertEqual(out1, out2)

    def test_refresh_replaces_in_place(self) -> None:
        header = "#pragma once\nclass TFoo {};\n"
        out1, _ = upsert_block(header, "TFoo", render_generated_block(_manifest()))
        # Manifest changes (object size) -> block refreshed, hand content intact, no dup block
        m2 = _manifest()
        m2["generated"]["object_size"] = "0x80"
        out2, changed = upsert_block(out1, "TFoo", render_generated_block(m2))
        self.assertTrue(changed)
        self.assertEqual(out2.count("BEGIN GENERATED (TFoo)"), 1)
        self.assertIn("object size 0x80", out2)
        self.assertIn("class TFoo {};", out2)

    def test_find_block_none_when_absent(self) -> None:
        self.assertIsNone(find_block("class TFoo {};\n", "TFoo"))


class ClassifiedFromManifestTests(unittest.TestCase):
    def test_reconstructs_slots_with_curated_name_winning(self) -> None:
        manifest = {
            "class": "TFoo",
            "generated": {
                "vtable_addr": "0x00650000",
                "base": "TObject",
                "slots": [
                    {"index": "0x00", "byte": "0x00", "target": "0x004b0000", "kind": "new", "ghidra_name": "TFoo::FUN_004b0000", "prototype": "int __thiscall f(int a)"},
                    {"index": "0x05", "byte": "0x14", "target": "0x004b0100", "kind": "override", "ghidra_name": "TFoo::WriteTo"},
                    {"index": "0x06", "byte": "0x18", "target": "0x00000000", "kind": "null"},
                ],
            },
            "curated": {"slots": [{"index": "0x00", "method": "ComputeThing"}]},
        }
        slots = _classified_from_manifest(manifest)
        self.assertEqual(len(slots), 3)
        s0 = slots[0]
        self.assertEqual(s0.kind, "new")
        self.assertEqual(s0.target_addr, "004b0000")  # bare hex
        self.assertIsNotNone(s0.sig)
        self.assertEqual(s0.sig.name, "ComputeThing")  # curated wins over Ghidra FUN_
        self.assertEqual(s0.sig.ret, "int")
        # null slot carries no signature
        self.assertIsNone(slots[2].sig)


if __name__ == "__main__":
    unittest.main()
