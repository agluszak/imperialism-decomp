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

from tools.binary.decode_builder import extract_cases


@dataclass
class _Insn:
    address: int
    mnemonic: str
    op_str: str
    size: int = 1


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


if __name__ == "__main__":
    unittest.main()
