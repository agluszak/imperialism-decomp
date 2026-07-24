"""Small PE32 and x86 helpers needed by debugger probe placement."""

from __future__ import annotations

from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86_const import X86_OP_IMM


def _mapped_bytes(path: Path, address: int, length: int) -> bytes:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise RuntimeError(f"not a PE executable: {path}")
    coff = pe_offset + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if struct.unpack_from("<H", data, optional)[0] != 0x10B:
        raise RuntimeError(f"not a PE32 executable: {path}")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    rva = address - image_base
    sections = optional + optional_size
    for index in range(section_count):
        section = sections + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, section + 8
        )
        mapped_size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + mapped_size:
            offset = raw_offset + rva - virtual_address
            return data[offset : offset + length]
    raise RuntimeError(f"address 0x{address:08x} is not mapped by {path}")


def _resolve_direct_thunk(executable: Path, address: int) -> int:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    instruction = next(
        iter(disassembler.disasm(_mapped_bytes(executable, address, 8), address)), None
    )
    if (
        instruction is not None
        and instruction.mnemonic == "jmp"
        and instruction.operands
        and instruction.operands[0].type == X86_OP_IMM
    ):
        return instruction.operands[0].imm
    return address


def direct_call_return(
    executable: Path, owner_address: int, callee_address: int, scan_bytes: int = 0x1000
) -> int:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    matches = []
    for instruction in disassembler.disasm(
        _mapped_bytes(executable, owner_address, scan_bytes), owner_address
    ):
        if (
            instruction.mnemonic == "call"
            and instruction.operands
            and instruction.operands[0].type == X86_OP_IMM
            and _resolve_direct_thunk(executable, instruction.operands[0].imm)
            == callee_address
        ):
            matches.append(instruction.address + instruction.size)
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one call from 0x{owner_address:08x} to 0x{callee_address:08x} "
            f"in {executable}, found {len(matches)}"
        )
    return matches[0]


def direct_call_target_after(
    executable: Path,
    owner_address: int,
    preceding_callee_address: int,
    scan_bytes: int = 0x1000,
) -> int:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    found_preceding = False
    for instruction in disassembler.disasm(
        _mapped_bytes(executable, owner_address, scan_bytes), owner_address
    ):
        if (
            instruction.mnemonic != "call"
            or not instruction.operands
            or instruction.operands[0].type != X86_OP_IMM
        ):
            continue
        target = instruction.operands[0].imm
        if found_preceding:
            return target
        if _resolve_direct_thunk(executable, target) == preceding_callee_address:
            found_preceding = True
    raise RuntimeError(
        f"could not find a direct call after 0x{preceding_callee_address:08x} "
        f"inside 0x{owner_address:08x} in {executable}"
    )
