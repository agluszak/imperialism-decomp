#!/usr/bin/env python3
"""Tests for decode_builder's eventCode case discovery (bd 1uj.51.5).

MSVC500 emits some switch cases as a binary-search ladder where a range jump
(and sometimes flag-preserving filler) sits between the `cmp eax, N` and the
equality `je`/`jne`. extract_cases must resolve those, not only the immediate
cmp/je form.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass
import struct

from tools.binary.decode_builder import extract_cases


@dataclass
class _Insn:
    address: int
    mnemonic: str
    op_str: str
    size: int = 1


class _Image:
    def __init__(self, address: int, values: list[int]) -> None:
        self.address = address
        self.data = struct.pack(f"<{len(values)}I", *values)

    def read_va(self, address: int, size: int) -> bytes:
        if address != self.address or size != len(self.data):
            raise AssertionError((address, size))
        return self.data


class _TablesImage:
    def __init__(self, tables: dict[int, bytes]) -> None:
        self.tables = tables

    def read_va(self, address: int, size: int) -> bytes:
        data = self.tables.get(address)
        if data is None or size != len(data):
            raise AssertionError((address, size))
        return data


def _seq(rows: list[tuple[str, str]], base: int = 0x1000) -> list[_Insn]:
    insns: list[_Insn] = []
    addr = base
    for mnemonic, op_str in rows:
        insns.append(_Insn(addr, mnemonic, op_str))
        addr += 4
    return insns


class ExtractCasesTests(unittest.TestCase):
    def test_immediate_cmp_je(self) -> None:
        insns = _seq([("cmp", "eax, 0x3b6"), ("je", "0x435818"), ("ret", "")])
        self.assertEqual(extract_cases(insns), {0x435818: {0x3B6}})

    def test_immediate_cmp_jne_falls_through(self) -> None:
        insns = _seq([("cmp", "eax, 0x3b6"), ("jne", "0x43b084"), ("push", "0xa0"), ("ret", "")])
        # equality case is the fall-through instruction after the jne
        self.assertEqual(extract_cases(insns), {insns[2].address: {0x3B6}})

    def test_cmp_then_range_jump_then_je(self) -> None:
        # 0x5de dispatch: cmp / jg / je (bd 1uj.51.5, real shape at 0x435e55)
        insns = _seq(
            [("cmp", "eax, 0x5de"), ("jg", "0x4368cc"), ("je", "0x435f2b"), ("ret", "")]
        )
        self.assertEqual(extract_cases(insns), {0x435F2B: {0x5DE}})

    def test_cmp_with_filler_and_range_jump_then_je(self) -> None:
        # 0x3ba dispatch: cmp / push / mov[mem] / jg / je (real shape at 0x4357d2)
        insns = _seq(
            [
                ("cmp", "eax, 0x3ba"),
                ("push", "edi"),
                ("mov", "dword ptr [0x6a141c], ebx"),
                ("jg", "0x435e55"),
                ("je", "0x435916"),
                ("ret", ""),
            ]
        )
        self.assertEqual(extract_cases(insns), {0x435916: {0x3BA}})

    def test_eax_redefined_before_je_is_not_a_case(self) -> None:
        # a `mov eax, ...` between the cmp and je kills the compare value
        insns = _seq(
            [("cmp", "eax, 0x100"), ("mov", "eax, ebx"), ("je", "0x2000"), ("ret", "")]
        )
        self.assertEqual(extract_cases(insns), {})

    def test_sub_dec_ladder_still_works(self) -> None:
        insns = _seq(
            [
                ("sub", "eax, 0x10"),
                ("je", "0x3000"),
                ("dec", "eax"),
                ("je", "0x3100"),
                ("ret", ""),
            ]
        )
        self.assertEqual(extract_cases(insns), {0x3000: {0x10}, 0x3100: {0x11}})

    def test_chained_sub_ladder_reports_original_event_codes(self) -> None:
        insns = _seq(
            [
                ("sub", "eax, 0x2103"),
                ("je", "0x3000"),
                ("sub", "eax, 0x31"),
                ("je", "0x3100"),
                ("sub", "eax, 0x12c"),
                ("je", "0x3200"),
                ("ret", ""),
            ]
        )
        self.assertEqual(
            extract_cases(insns),
            {0x3000: {0x2103}, 0x3100: {0x2134}, 0x3200: {0x2260}},
        )

    def test_direct_word_parameter_comparison(self) -> None:
        insns = _seq(
            [
                ("push", "esi"),
                ("cmp", "word ptr [esp + 0x30], 0x7de"),
                ("je", "0x46fd4c"),
                ("ret", ""),
            ]
        )
        self.assertEqual(extract_cases(insns), {0x46FD4C: {0x7DE}})

    def test_unreachable_body_comparison_is_not_a_dispatch_case(self) -> None:
        insns = _seq(
            [
                ("cmp", "eax, 0x7de"),
                ("je", "0x2000"),
                ("ret", ""),
                ("cmp", "eax, 0x1234"),
                ("je", "0x4000"),
            ]
        )
        self.assertEqual(extract_cases(insns), {0x2000: {0x7DE}})

    def test_bounded_jump_table_uses_normalized_event_codes_and_skips_default(self) -> None:
        default = 0x9000
        targets = [0x2000, 0x2100, default, 0x2300, 0x2400, default, 0x2600, default, default, 0x2900]
        image = _Image(0x5000, targets)
        insns = _seq(
            [
                ("add", "eax, 0xfffffa24"),
                ("cmp", "eax, 0x9"),
                ("ja", hex(default)),
                ("jmp", "dword ptr [eax*4 + 0x5000]"),
                ("ret", ""),
            ]
        )

        self.assertEqual(
            extract_cases(insns, image),
            {
                0x2000: {0x5DC},
                0x2100: {0x5DD},
                0x2300: {0x5DF},
                0x2400: {0x5E0},
                0x2600: {0x5E2},
                0x2900: {0x5E5},
            },
        )

    def test_sparse_byte_index_jump_table_reports_original_event_codes(self) -> None:
        default = 0x9000
        index_table = 0x6000
        target_table = 0x6100
        indices = bytes([0, 1, 2, 3, 2])
        targets = [0x2000, default, 0x2200, 0x2300]
        image = _TablesImage(
            {
                index_table: indices,
                target_table: struct.pack(f"<{len(targets)}I", *targets),
            }
        )
        insns = _seq(
            [
                ("add", "eax, 0xffffdb0a"),
                ("cmp", "eax, 0x4"),
                ("ja", hex(default)),
                ("xor", "ecx, ecx"),
                ("mov", f"cl, byte ptr [eax + {index_table:#x}]"),
                ("jmp", f"dword ptr [ecx*4 + {target_table:#x}]"),
                ("ret", ""),
            ]
        )

        self.assertEqual(
            extract_cases(insns, image),
            {
                0x2000: {0x24F6},
                0x2200: {0x24F8, 0x24FA},
                0x2300: {0x24F9},
            },
        )


if __name__ == "__main__":
    unittest.main()
