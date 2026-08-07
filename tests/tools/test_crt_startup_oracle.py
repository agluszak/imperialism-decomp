#!/usr/bin/env python3
from __future__ import annotations

import struct
import unittest

from tools.reccmp.crt_startup_oracle import CrtArrayRange, recover_init_ranges


def call_sequence(at: int, target: int, start: int, end: int) -> bytes:
    prefix = b"\x68" + struct.pack("<I", end) + b"\x68" + struct.pack("<I", start)
    call_at = at + len(prefix)
    return prefix + b"\xe8" + struct.pack("<i", target - (call_at + 5))


class CrtStartupOracleTests(unittest.TestCase):
    def test_recovers_ranges_in_call_order(self) -> None:
        base = 0x401000
        target = 0x402000
        first = call_sequence(base, target, 0x600100, 0x600120)
        second_at = base + len(first) + 3
        code = first + b"\x83\xc4\x08" + call_sequence(second_at, target, 0x601000, 0x601080)
        self.assertEqual(
            recover_init_ranges(code, base, target),
            [CrtArrayRange(0x600100, 0x600120), CrtArrayRange(0x601000, 0x601080)],
        )

    def test_ignores_other_call_targets(self) -> None:
        code = call_sequence(0x401000, 0x403000, 0x600100, 0x600120)
        self.assertEqual(recover_init_ranges(code, 0x401000, 0x402000), [])

    def test_rejects_non_dword_aligned_range(self) -> None:
        code = call_sequence(0x401000, 0x402000, 0x600101, 0x600120)
        self.assertEqual(recover_init_ranges(code, 0x401000, 0x402000), [])


if __name__ == "__main__":
    unittest.main()
