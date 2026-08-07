import struct
import unittest

from tools.reccmp.zero_size_data_audit import FunctionExtent, categorize


class FakeImage:
    image_base = 0x400000
    sections = [(0x1000, 0, 0x1000), (0x3000, 0, 0x1000)]

    def __init__(self, pointers=()):
        self.pointers = list(pointers)

    def jmp_target(self, address):
        return 0x401500 if address == 0x401400 else None

    def read_va(self, address, size):
        index = (address - 0x403000) // 4
        if index < 0 or index >= len(self.pointers):
            raise ValueError(address)
        return struct.pack("<I", self.pointers[index])


class ZeroSizeDataAuditTests(unittest.TestCase):
    def test_text_interior_uses_curated_extent_evidence(self):
        functions = [FunctionExtent(0x401100, 0x20, "Owner")]
        result = categorize(0x401108, 1, functions, FakeImage())
        self.assertEqual(result[0:2], ("function_interior", "label"))
        self.assertIn("Owner", result[2])

    def test_e9_is_thunk_evidence_but_uncovered_text_is_not_guessed(self):
        self.assertEqual(categorize(0x401400, 1, [], FakeImage())[0:2],
                         ("relative_jump", "thunk"))
        self.assertEqual(categorize(0x401404, 1, [], FakeImage())[0:2],
                         ("uncovered_text", "manual_listing"))

    def test_pointer_run_is_only_a_vtable_candidate(self):
        image = FakeImage([0x401100, 0x401200, 0x401300, 0])
        self.assertEqual(categorize(0x403000, 2, [], image)[0:2],
                         ("code_pointer_run", "vtable_candidate"))


if __name__ == "__main__":
    unittest.main()
