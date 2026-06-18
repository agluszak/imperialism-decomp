#!/usr/bin/env python3
"""Tests for tools.workflow.gen_class (marked-region render + idempotent upsert)."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.common import class_manifest as cm
from tools.workflow.gen_class import (
    classified_from_manifest,
    existing_vtable_annotation,
    find_block,
    render_generated_block,
    source_base_scaffold_issues,
    upsert_block,
)


class AncestryOverrideNamingTests(unittest.TestCase):
    def _write(self, repo_root: Path, manifest: dict) -> None:
        cdir = repo_root / "config" / "classes"
        cdir.mkdir(parents=True, exist_ok=True)
        cm.write_manifest(cdir / f"{manifest['class']}.yml", manifest)

    def test_override_adopts_parent_name_and_signature(self) -> None:
        base = {
            "class": "TBase",
            "generated": {
                "vtable_addr": "0x00650000",
                "base": "TObject",
                "ancestry": ["TBase", "TObject"],
                "slots": [
                    {"index": "0x0a", "byte": "0x28", "target": "0x004b0a00", "kind": "new",
                     "ghidra_name": "TBase::FUN_004b0a00", "prototype": "void __thiscall f(int x)"},
                ],
            },
            "curated": {"slots": [{"index": "0x0a", "method": "DoBaseThing"}]},
        }
        derived = {
            "class": "TDerived",
            "generated": {
                "vtable_addr": "0x00660000",
                "base": "TBase",
                "ancestry": ["TDerived", "TBase", "TObject"],
                "slots": [
                    {"index": "0x0a", "byte": "0x28", "target": "0x004c0a00", "kind": "override",
                     "ghidra_name": "TDerived::FUN_004c0a00", "prototype": "void __thiscall g(int y)"},
                ],
            },
            "curated": {},
        }
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            self._write(repo_root, base)
            self._write(repo_root, derived)
            slots = {s.index: s for s in classified_from_manifest(derived, repo_root)}
            slot = slots[10]
            self.assertEqual(slot.kind, "override")
            # Adopts the parent virtual's name + signature so it really overrides.
            self.assertEqual(slot.sig.name, "DoBaseThing")
            self.assertEqual(slot.sig.args, "int x")

    def test_local_curated_name_wins_over_parent(self) -> None:
        base = {
            "class": "TBase",
            "generated": {
                "base": "TObject", "ancestry": ["TBase", "TObject"],
                "slots": [{"index": "0x0a", "byte": "0x28", "target": "0x004b0a00", "kind": "new",
                           "ghidra_name": "TBase::x", "prototype": "void f()"}],
            },
            "curated": {"slots": [{"index": "0x0a", "method": "DoBaseThing"}]},
        }
        derived = {
            "class": "TDerived",
            "generated": {
                "base": "TBase", "ancestry": ["TDerived", "TBase", "TObject"],
                "slots": [{"index": "0x0a", "byte": "0x28", "target": "0x004c0a00", "kind": "override",
                           "ghidra_name": "TDerived::x", "prototype": "void g()"}],
            },
            "curated": {"slots": [{"index": "0x0a", "method": "DerivedSpecial"}]},
        }
        with TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            self._write(repo_root, base)
            self._write(repo_root, derived)
            slots = {s.index: s for s in classified_from_manifest(derived, repo_root)}
            self.assertEqual(slots[10].sig.name, "DerivedSpecial")


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
        slots = classified_from_manifest(manifest)
        self.assertEqual(len(slots), 3)
        s0 = slots[0]
        self.assertEqual(s0.kind, "override")
        self.assertEqual(s0.target_addr, "4b0000")  # bare hex, no leading zeroes
        self.assertIsNotNone(s0.sig)
        # TObject's source-owned slot 0 supplies the real override signature.
        self.assertEqual(s0.sig.name, "GetRuntimeClass")
        self.assertEqual(s0.sig.ret, "CRuntimeClass*")
        # null slot carries no signature
        self.assertIsNone(slots[2].sig)

    def test_source_owned_tobject_slots_correct_manifest_kinds(self) -> None:
        manifest = {
            "class": "TFoo",
            "generated": {
                "base": "TObject",
                "slots": [
                    {"index": "0x00", "byte": "0x00", "target": "0x00500000", "kind": "new", "ghidra_name": "TFoo::GetTFooClassNamePointer"},
                    {"index": "0x01", "byte": "0x04", "target": "0x00500020", "kind": "new", "ghidra_name": "TFoo::DestroyTFoo"},
                    {"index": "0x02", "byte": "0x08", "target": "0x00485e90", "kind": "new", "ghidra_name": "Wrong::Name"},
                    {"index": "0x03", "byte": "0x0c", "target": "0x00412bf0", "kind": "new", "ghidra_name": "Wrong::Name"},
                    {"index": "0x04", "byte": "0x10", "target": "0x00412c10", "kind": "new", "ghidra_name": "Wrong::Name"},
                    {"index": "0x05", "byte": "0x14", "target": "0x00500100", "kind": "new", "ghidra_name": "TFoo::WriteState"},
                ],
            },
            "curated": {},
        }
        slots = {s.index: s for s in classified_from_manifest(manifest)}
        self.assertEqual(slots[0].kind, "override")
        self.assertEqual(slots[0].sig.name, "GetRuntimeClass")
        self.assertEqual(slots[1].kind, "scalar_dtor")
        self.assertEqual(slots[2].kind, "inherited")
        self.assertEqual(slots[2].qualified_name, "TObject::Serialize")
        self.assertEqual(slots[3].kind, "inherited")
        self.assertEqual(slots[3].qualified_name, "CObject::AssertValid")
        self.assertEqual(slots[4].kind, "inherited")
        self.assertEqual(slots[4].qualified_name, "CObject::Dump")
        self.assertEqual(slots[5].kind, "override")
        self.assertEqual(slots[5].sig.name, "WriteTo")

    def test_source_base_scaffold_issue_for_shorter_than_tobject_table(self) -> None:
        manifest = _manifest()
        manifest["class"] = "TShort"
        manifest["generated"]["slots"] = manifest["generated"]["slots"][:2]
        issues = source_base_scaffold_issues("TShort", manifest)
        self.assertEqual(len(issues), 1)
        self.assertIn("source-modeled TObject reaches slot 0x09", issues[0])


class ExistingVtableAnnotationTests(unittest.TestCase):
    def test_finds_existing_owner_header(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            include_game = root / "include" / "game"
            include_game.mkdir(parents=True)
            (include_game / "TMapOrderContext.h").write_text(
                "#pragma once\n"
                "// VTABLE: IMPERIALISM 0x0065c7c8\n"
                "class TMapOrderContext {};\n",
                encoding="utf-8",
            )
            owner = existing_vtable_annotation(root, "TOcean", "0x0065c7c8")
            self.assertIsNotNone(owner)
            self.assertIn("TMapOrderContext", owner)
            self.assertIn("include/game/TMapOrderContext.h:2", owner)

    def test_ignores_target_class_header(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            include_game = root / "include" / "game"
            include_game.mkdir(parents=True)
            (include_game / "TFoo.h").write_text(
                "#pragma once\n// VTABLE: IMPERIALISM 0x1\nclass TFoo {};\n",
                encoding="utf-8",
            )
            self.assertIsNone(existing_vtable_annotation(root, "TFoo", "0x00000001"))


if __name__ == "__main__":
    unittest.main()
