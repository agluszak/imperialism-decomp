#!/usr/bin/env python3
"""Tests for tools.workflow.shape_body."""

from __future__ import annotations

import unittest

from tools.common.thunk_names import ThunkResolver
from tools.workflow.class_codegen import ClassifiedSlot, Signature
from tools.workflow.shape_body import shape_body


def _slot(sig: Signature | None, target: str = "00562190", kind: str = "override") -> ClassifiedSlot:
    return ClassifiedSlot(
        index=0,
        byte_offset=0,
        slot_label="0x00",
        target_addr=target,
        kind=kind,
        sig=sig,
        qualified_name="GetRuntimeClass",
        size=6,
        prototype=None,
        decompiled_c=None,
        base_target=None,
    )


_GETTER_BLOCK = (
    "// GHIDRA_FUNCTION IMPERIALISM 0x00562190\n"
    "// GHIDRA_NAME TOcean::GetTOceanClassNamePointer\n"
    "// GHIDRA_PROTO undefined __thiscall GetTOceanClassNamePointer(void)\n"
    "\n"
    "CRuntimeClass * __thiscall TOcean::GetTOceanClassNamePointer(TOcean *this)\n"
    "\n"
    "{\n"
    "  return &classRuntimeClass;\n"
    "}\n"
)


class ShapeSignatureTests(unittest.TestCase):
    def test_rewrites_signature_to_declared_method(self) -> None:
        sig = Signature(ret="CRuntimeClass*", name="GetRuntimeClass", args="", const=" const")
        out = shape_body(_GETTER_BLOCK, _slot(sig), "TOcean")
        self.assertIn("// FUNCTION: IMPERIALISM 0x00562190", out)
        self.assertIn("CRuntimeClass* TOcean::GetRuntimeClass() const {", out)
        # Ghidra junk gone from the signature line.
        self.assertNotIn("__thiscall", out)
        self.assertNotIn("GetTOceanClassNamePointer", out)
        self.assertNotIn("TOcean *this", out)
        # Body preserved.
        self.assertIn("return &classRuntimeClass;", out)

    def test_no_todo_when_body_is_clean(self) -> None:
        sig = Signature(ret="CRuntimeClass*", name="GetRuntimeClass", args="", const=" const")
        out = shape_body(_GETTER_BLOCK, _slot(sig), "TOcean")
        self.assertNotIn("TODO(shape)", out)

    def test_fallback_when_no_signature(self) -> None:
        out = shape_body(_GETTER_BLOCK, _slot(None), "TOcean")
        self.assertIn("// FUNCTION: IMPERIALISM 0x00562190", out)
        # Without a recovered signature we keep the raw body verbatim.
        self.assertIn("GetTOceanClassNamePointer", out)


class ShapeInStackTests(unittest.TestCase):
    def test_lifts_in_stack_to_declared_param(self) -> None:
        block = (
            "// GHIDRA_FUNCTION IMPERIALISM 0x005628f0\n"
            "void __thiscall TOcean::Foo(TOcean *this)\n"
            "{\n"
            "  short in_stack_00000004;\n"
            "  this->count = in_stack_00000004 + 1;\n"
            "}\n"
        )
        sig = Signature(ret="void", name="WriteTo", args="short value", const="")
        out = shape_body(block, _slot(sig, target="005628f0"), "TOcean")
        self.assertIn("void TOcean::WriteTo(short value)", out)
        # The local `short in_stack_00000004;` declaration is dropped (now a param),
        # not renamed — otherwise the parameter would be shadowed by a local.
        self.assertNotIn("short value;", out)
        self.assertIn("this->count = value + 1;", out)
        self.assertNotIn("in_stack_", out)
        self.assertNotIn("TODO(shape)", out)

    def test_flags_unliftable_in_stack(self) -> None:
        block = (
            "// GHIDRA_FUNCTION IMPERIALISM 0x005628f0\n"
            "void __thiscall TOcean::Foo(TOcean *this)\n"
            "{\n"
            "  short in_stack_00000004;\n"
            "  int in_stack_00000008;\n"
            "  this->count = in_stack_00000004;\n"
            "}\n"
        )
        sig = Signature(ret="void", name="WriteTo", args="", const="")  # no params to map onto
        out = shape_body(block, _slot(sig, target="005628f0"), "TOcean")
        self.assertIn("TODO(shape)", out)
        self.assertIn("in_stack_", out)  # left for the human


class ShapeThunkTests(unittest.TestCase):
    def test_resolves_thunk_names_in_body(self) -> None:
        block = (
            "// GHIDRA_FUNCTION IMPERIALISM 0x00562190\n"
            "void __thiscall TOcean::Foo(TOcean *this)\n"
            "{\n"
            "  thunk_DoWork(this);\n"
            "}\n"
        )
        sig = Signature(ret="void", name="DoStuff", args="", const="")
        resolver = ThunkResolver({"thunk_DoWork": "TWorker::DoWork"})
        out = shape_body(block, _slot(sig), "TOcean", resolver)
        self.assertIn("TWorker::DoWork(this);", out)
        self.assertNotIn("thunk_DoWork", out)


class ShapeHazardTests(unittest.TestCase):
    def test_flags_vftable_and_eh_frame(self) -> None:
        block = (
            "// GHIDRA_FUNCTION IMPERIALISM 0x0057c9a0\n"
            "void __thiscall TOcean::Foo(TOcean *this)\n"
            "{\n"
            "  undefined4 *unaff_FS_OFFSET;\n"
            "  *unaff_FS_OFFSET = 0;\n"
            "  (*this->vftable[3].slot)();\n"
            "}\n"
        )
        sig = Signature(ret="void", name="Recreate", args="", const="")
        out = shape_body(block, _slot(sig, target="0057c9a0"), "TOcean")
        self.assertIn("// TODO(shape):", out)
        self.assertIn("EH frame", out)
        self.assertIn("vtable dispatch", out)
        # Signature is still corrected even when the body is flagged.
        self.assertIn("void TOcean::Recreate()", out)


if __name__ == "__main__":
    unittest.main()
