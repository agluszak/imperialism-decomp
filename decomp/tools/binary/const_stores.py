#!/usr/bin/env python3
"""Extract the ordered (global-address -> constant value) store map of an
unrolled table-initializer function, straight from the original binary.

Disassembles the function with capstone (structured operands — no listing-text
parsing), tracks register constants (MOV reg,imm / XOR reg,reg / OR reg,-1 and
the 16-bit forms), and records every store to an absolute data address in
original store order. Loops/indexed stores are reported as untracked so nothing
is silently missed.

Output: one line per store `seq fileaddr [target] width = value`, an extent and
double-write summary, and (with --cpp ARRAYNAME:BASE:STRIDE:f0,f1,..) generated
C++ assignment lines for regenerating the initializer as source.

usage:
  uv run python -m tools.binary.const_stores 0xADDR [--len N]
  uv run python -m tools.binary.const_stores 0xADDR --cpp g_tbl:0x6a4780:8:dx,dy
"""

from __future__ import annotations

import sys

import capstone
from capstone import x86

from tools.binary.pe import OriginalImage, load_symbol_sizes

_CONST_SETTERS = ("mov", "xor", "or", "sub")


def _reg_root(md, reg) -> int:
  """Collapse ax/al/ah -> eax etc. so sub-register stores hit the tracked value."""
  m = {
      x86.X86_REG_AX: x86.X86_REG_EAX, x86.X86_REG_AL: x86.X86_REG_EAX,
      x86.X86_REG_AH: None, x86.X86_REG_BX: x86.X86_REG_EBX,
      x86.X86_REG_BL: x86.X86_REG_EBX, x86.X86_REG_BH: None,
      x86.X86_REG_CX: x86.X86_REG_ECX, x86.X86_REG_CL: x86.X86_REG_ECX,
      x86.X86_REG_CH: None, x86.X86_REG_DX: x86.X86_REG_EDX,
      x86.X86_REG_DL: x86.X86_REG_EDX, x86.X86_REG_DH: None,
      x86.X86_REG_SI: x86.X86_REG_ESI, x86.X86_REG_DI: x86.X86_REG_EDI,
      x86.X86_REG_BP: x86.X86_REG_EBP, x86.X86_REG_SP: x86.X86_REG_ESP,
  }
  return m.get(reg, reg)


def extract(addr: int, length: int | None = None):
  img = OriginalImage()
  if length is None:
    length = load_symbol_sizes().get(addr, 0x2000)
  code = img.read_va(addr, length)
  md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
  md.detail = True

  regs: dict[int, int | None] = {}
  stores: list[tuple[int, int, int, int | None]] = []  # insn va, target, width, value
  untracked: list[str] = []
  for ins in md.disasm(code, addr):
    if ins.mnemonic == "ret":
      break
    ops = ins.operands
    if ins.mnemonic == "mov" and len(ops) == 2:
      dst, src = ops
      if dst.type == x86.X86_OP_MEM:
        if dst.mem.base == 0 and dst.mem.index == 0 and dst.mem.disp >= 0x40_0000:
          if src.type == x86.X86_OP_IMM:
            val: int | None = src.imm & (2**(8 * dst.size) - 1)
          else:
            root = _reg_root(md, src.reg)
            val = regs.get(root) if root is not None else None
            if val is not None:
              val &= 2**(8 * dst.size) - 1
          stores.append((ins.address, dst.mem.disp, dst.size, val))
        elif dst.mem.base not in (x86.X86_REG_ESP, x86.X86_REG_EBP):
          untracked.append(f"  ? 0x{ins.address:08x}  {ins.mnemonic} {ins.op_str}")
        continue
      if dst.type == x86.X86_OP_REG:
        root = _reg_root(md, dst.reg)
        if src.type == x86.X86_OP_IMM and dst.size == 4:
          regs[root] = src.imm & 0xFFFFFFFF
        elif root is not None:
          regs[root] = None
        continue
    # xor r,r / or r,-1 / sub r,r
    if ins.mnemonic in ("xor", "sub") and len(ops) == 2 and \
       ops[0].type == ops[1].type == x86.X86_OP_REG and ops[0].reg == ops[1].reg:
      regs[_reg_root(md, ops[0].reg)] = 0
      continue
    if ins.mnemonic == "or" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and \
       ops[1].type == x86.X86_OP_IMM and ops[1].imm in (-1, 0xFFFFFFFF):
      regs[_reg_root(md, ops[0].reg)] = 0xFFFFFFFF
      continue
    # anything else that writes a register invalidates it
    if ops and ops[0].type == x86.X86_OP_REG and ins.mnemonic not in ("cmp", "test", "push"):
      root = _reg_root(md, ops[0].reg)
      if root is not None:
        regs[root] = None
  return stores, untracked


def main() -> int:
  args = [a for a in sys.argv[1:]]
  if not args:
    print(__doc__, file=sys.stderr)
    return 2
  addr = int(args[0], 16)
  length = None
  cpp_spec = None
  if "--len" in args:
    length = int(args[args.index("--len") + 1], 0)
  if "--cpp" in args:
    cpp_spec = args[args.index("--cpp") + 1]

  stores, untracked = extract(addr, length)
  if cpp_spec is None:
    print(f"const-stores 0x{addr:08x}: {len(stores)} stores")
    if stores:
      lo = min(t for _, t, _, _ in stores)
      hi = max(t + w for _, t, w, _ in stores)
      print(f"  extent: 0x{lo:08x}..0x{hi:08x}  span {hi - lo} bytes")
      seen: dict[int, int] = {}
      for _, t, _, _ in stores:
        seen[t] = seen.get(t, 0) + 1
      doubles = {t: n for t, n in seen.items() if n > 1}
      if doubles:
        print(f"  double-written addresses: {len(doubles)}")
    for seq, (ia, tgt, width, val) in enumerate(stores):
      sval = "?" if val is None else str(val - 2**(8 * width) if val >= 2**(8 * width - 1) else val)
      print(f"  {seq:4d}  0x{ia:08x}  [0x{tgt:08x}] w{width} = {sval}")
  else:
    name, base, stride, fields = cpp_spec.split(":")
    base = int(base, 16)
    stride = int(stride, 0)
    fields = fields.split(",")
    for _, tgt, width, val in stores:
      off = tgt - base
      idx, fld_off = divmod(off, stride)
      fld = fields[fld_off // (stride // len(fields))] if fld_off % (stride // len(fields)) == 0 \
          else f"/*+0x{fld_off:x}*/"
      sval = "?" if val is None else str(val - 2**(8 * width) if val >= 2**(8 * width - 1) else val)
      print(f"  {name}[{idx}].{fld} = {sval};")
  if untracked:
    print(f"-- {len(untracked)} untracked (indexed/looped) stores --")
    for line in untracked[:30]:
      print(line)
  return 0


if __name__ == "__main__":
  sys.exit(main())
