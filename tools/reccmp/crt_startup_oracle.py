#!/usr/bin/env python3
"""Recover original CRT initializer-array boundaries from ``__cinit``.

Retail PDB-less images do not expose ``___xi_a/z`` and ``___xc_a/z``.  Reccmp's
initializer matcher requires those names, while the linked ``__cinit`` body already
contains the exact ranges as arguments to ``__initterm``.  This oracle decodes that
stable CRT contract and emits an ephemeral reccmp data source; it does not curate or
rename gameplay symbols.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.mfc.pe_image import PEImage
from tools.mfc.build_library_oracle import resolve_binary

DEFAULT_SYMBOLS = "config/original_entities.csv"
DEFAULT_OUT = "build-msvc500/evidence/crt_startup_boundaries.csv"


@dataclass(frozen=True)
class CrtArrayRange:
    start: int
    end: int


def recover_init_ranges(
    code: bytes, code_address: int, initterm_address: int
) -> list[CrtArrayRange]:
    """Return each ``__initterm(start, end)`` range in call order.

    VC5 pushes ``end`` and then ``start`` immediately before the cdecl call.  Any
    different shape is ignored instead of guessed.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(code, code_address))
    ranges: list[CrtArrayRange] = []
    for index, inst in enumerate(instructions):
        if inst.mnemonic != "call" or len(inst.operands) != 1:
            continue
        operand = inst.operands[0]
        if operand.type != X86_OP_IMM or operand.imm != initterm_address or index < 2:
            continue
        push_end, push_start = instructions[index - 2 : index]
        if push_end.mnemonic != "push" or push_start.mnemonic != "push":
            continue
        if len(push_end.operands) != 1 or len(push_start.operands) != 1:
            continue
        if push_end.operands[0].type != X86_OP_IMM or push_start.operands[0].type != X86_OP_IMM:
            continue
        start = int(push_start.operands[0].imm) & 0xFFFFFFFF
        end = int(push_end.operands[0].imm) & 0xFFFFFFFF
        if start < end and (end - start) % 4 == 0:
            ranges.append(CrtArrayRange(start, end))
    return ranges


def _function_row(rows: list[dict[str, str]], symbol: str) -> tuple[int, int]:
    hits = [row for row in rows if (row.get("symbol") or "").strip() == symbol]
    if len(hits) != 1:
        raise ValueError(f"expected one {symbol} row, found {len(hits)}")
    return int(hits[0]["address"], 16), int(hits[0]["size"])


def recover_from_image(binary: Path, symbols: Path) -> dict[str, int]:
    rows = list(read_pipe_rows(symbols))
    cinit_address, cinit_size = _function_row(rows, "__cinit")
    initterm_address, _ = _function_row(rows, "__initterm")
    image = PEImage(binary)
    code = image.read_va(cinit_address, cinit_size)
    if code is None:
        raise ValueError(f"cannot read __cinit at 0x{cinit_address:08x}")
    ranges = recover_init_ranges(code, cinit_address, initterm_address)
    if len(ranges) != 2:
        raise ValueError(f"expected C and C++ initializer ranges, found {len(ranges)}")
    # VC CRT startup order is C initializers (__xi) followed by C++ (__xc).
    c_init, cpp_init = ranges
    return {
        "___xi_a": c_init.start,
        "___xi_z": c_init.end,
        "___xc_a": cpp_init.start,
        "___xc_z": cpp_init.end,
    }


def write_boundaries(path: Path, labels: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(
            fd,
            fieldnames=("address", "name", "type"),
            delimiter="|",
            lineterminator="\n",
        )
        writer.writeheader()
        for name, address in labels.items():
            writer.writerow({"address": f"0x{address:08x}", "name": name, "type": "global"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        default=None,
        help="original executable (default: $ORIGINAL_BINARY or orig/Imperialism.exe)",
    )
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--out", default=DEFAULT_OUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root_from_file(__file__)
    binary = resolve_binary(root, args.binary)
    symbols = resolve_repo_path(root, args.symbols)
    out = resolve_repo_path(root, args.out)
    labels = recover_from_image(binary, symbols)
    write_boundaries(out, labels)
    print(f"CRT startup boundaries -> {out}")
    for name, address in labels.items():
        print(f"  {name}: 0x{address:08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
