#!/usr/bin/env python3
"""Tests for tools.workflow.emit_class_slots."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.workflow.emit_class_slots import (
    autogen_to_manual_block,
    merge_cpp_bodies,
    scalar_dtor_block,
)
from tools.workflow.class_codegen import ClassifiedSlot
from tools.workflow.gen_class import (
    classified_from_manifest,
    render_generated_decls,
    upsert_decls_block,
)


def _tocean_manifest() -> dict:
    return {
        "class": "TOcean",
        "generated": {
            "vtable_addr": "0x0065c7c8",
            "object_size": "0x18",
            "base": "TObject",
            "slots": [
                {"index": "0x00", "byte": "0x00", "target": "0x00562190", "kind": "new", "ghidra_name": "TOcean::GetTOceanClassNamePointer", "prototype": "undefined GetTOceanClassNamePointer()"},
                {"index": "0x01", "byte": "0x04", "target": "0x00562140", "kind": "new", "ghidra_name": "TOcean::DestroyTPortZoneManager", "prototype": "undefined DestroyTPortZoneManager()"},
                {"index": "0x02", "byte": "0x08", "target": "0x00485e90", "kind": "new", "ghidra_name": "Wrong::Name", "prototype": "undefined x()"},
                {"index": "0x03", "byte": "0x0c", "target": "0x00412bf0", "kind": "new", "ghidra_name": "Wrong::Name", "prototype": "undefined x()"},
                {"index": "0x04", "byte": "0x10", "target": "0x00412c10", "kind": "new", "ghidra_name": "Wrong::Name", "prototype": "undefined x()"},
                {"index": "0x05", "byte": "0x14", "target": "0x005628f0", "kind": "new", "ghidra_name": "LinkedListQueryOwner::SerializeMapActionContextRuntimeState", "prototype": "undefined SerializeMapActionContextRuntimeState()"},
                {"index": "0x06", "byte": "0x18", "target": "0x00562340", "kind": "new", "ghidra_name": "LinkedListQueryOwner::DeserializeMapActionContextRuntimeState", "prototype": "undefined DeserializeMapActionContextRuntimeState()"},
            ],
        },
        "curated": {
            "slots": [
                {"index": "0x00", "method": "GetRuntimeClass"},
                {"index": "0x05", "method": "WriteTo"},
                {"index": "0x06", "method": "ReadFrom"},
            ],
        },
    }


class EmitClassSlotsTests(unittest.TestCase):
    def test_decls_block_inserts_after_public(self) -> None:
        header = (
            "#pragma once\n"
            "class TOcean : public TObject {\n"
            "public:\n"
            "  short nationCount;\n"
            "};\n"
        )
        manifest = _tocean_manifest()
        slots = classified_from_manifest(manifest)
        emit = [s for s in slots if s.kind not in ("null", "ilt_thunk")]
        block = render_generated_decls(manifest, emit)
        out, changed = upsert_decls_block(header, "TOcean", block)
        self.assertTrue(changed)
        self.assertIn("BEGIN GENERATED DECLS (TOcean)", out)
        self.assertIn("WriteTo(TStream* stream) override", out)
        self.assertLess(out.index("BEGIN GENERATED DECLS"), out.index("nationCount"))

    def test_autogen_to_manual_rewrites_marker(self) -> None:
        block = (
            "// GHIDRA_FUNCTION IMPERIALISM 0x00562190\n"
            "// GHIDRA_NAME TOcean::GetTOceanClassNamePointer\n"
            "void foo() {}\n"
        )
        out = autogen_to_manual_block(block, 0x562190)
        self.assertIn("// FUNCTION: IMPERIALISM 0x00562190", out)
        self.assertNotIn("GHIDRA_FUNCTION", out)

    def test_scalar_dtor_block(self) -> None:
        self.assertIn("SYNTHETIC", scalar_dtor_block("TOcean", 0x562140))
        self.assertIn("scalar deleting destructor", scalar_dtor_block("TOcean", 0x562140))

    def test_merge_cpp_preserves_existing_and_orders(self) -> None:
        cpp = (
            "#include \"game/TOcean.h\"\n\n"
            "// FUNCTION: IMPERIALISM 0x005634a0\n"
            "void* TOcean::FindPortZoneBySelectedTile(TCity* city) { return 0; }\n\n"
        )
        slot = ClassifiedSlot(
            index=0,
            byte_offset=0,
            slot_label="0x00",
            target_addr="562190",
            kind="override",
            sig=None,
            qualified_name="GetRuntimeClass",
            size=6,
            prototype=None,
            decompiled_c=None,
            base_target=None,
        )
        autogen = {
            0x562190: "// GHIDRA_FUNCTION IMPERIALISM 0x00562190\nvoid x() {}\n",
        }
        out, promoted, missing = merge_cpp_bodies(cpp, "TOcean", [slot], autogen)
        self.assertEqual(promoted, [0x562190])
        self.assertEqual(missing, [])
        lines = out.splitlines()
        idx_fn = next(i for i, ln in enumerate(lines) if "0x00562190" in ln)
        idx_find = next(i for i, ln in enumerate(lines) if "0x005634a0" in ln)
        self.assertLess(idx_fn, idx_find)


if __name__ == "__main__":
    unittest.main()
