"""Coverage for the UI factory widget fingerprint floor's pure pieces."""

from __future__ import annotations

import struct
from pathlib import Path
import unittest

from tools.workflow.check_ui_factory_widgets import (
    WidgetFingerprint,
    load_reclass_equivalent,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeImage:
    """Minimal stand-in for RetailImage: `read` over a flat buffer."""

    def __init__(self, data: bytes, base: int = 0x400000):
        self.data = data
        self.base = base

    def read(self, va: int, n: int) -> bytes:
        off = va - self.base
        return self.data[off : off + n]


def fingerprint_for(data: bytes, base: int = 0x400000) -> WidgetFingerprint:
    return WidgetFingerprint(FakeImage(data, base), {}, {}, {})


class ReclassEquivalentTests(unittest.TestCase):
    def test_post_create_rows_derive_the_equivalence(self) -> None:
        equivalent = load_reclass_equivalent(REPO_ROOT)
        self.assertEqual(
            equivalent.get("TRightLeftView"), "TSidewaysArrow"
        )
        # Factory-level substitutions are NOT equivalences: the retail builder
        # itself constructs the Windows class there.
        self.assertNotIn("TTEView", equivalent)


class ResolveThunkTests(unittest.TestCase):
    def test_e9_jump_is_followed(self) -> None:
        # thunk at base+0: E9 +5 -> target at base+0x10
        data = bytearray(0x20)
        data[0] = 0xE9
        struct.pack_into("<i", data, 1, 0x10 - 5)
        fp = fingerprint_for(bytes(data))
        self.assertEqual(fp.resolve_thunk(0x400000), 0x400010)

    def test_non_thunk_returns_input(self) -> None:
        fp = fingerprint_for(b"\x90" * 0x20)
        self.assertEqual(fp.resolve_thunk(0x400005), 0x400005)


class CtorVtableTests(unittest.TestCase):
    def test_vftable_store_found(self) -> None:
        # mov dword ptr [ecx], 0x650000 ; ret
        data = b"\xc7\x01\x00\x00\x65\x00" + b"\xc3"
        fp = fingerprint_for(data)
        fp.vtables = {0x650000: "TThing"}
        self.assertEqual(fp.ctor_vtable(0x400000), 0x650000)

    def test_no_store_returns_none(self) -> None:
        data = b"\x55\x8b\xec" + b"\xc3"
        fp = fingerprint_for(data)
        fp.vtables = {0x650000: "TThing"}
        self.assertIsNone(fp.ctor_vtable(0x400000))


if __name__ == "__main__":
    unittest.main()
