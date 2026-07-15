#!/usr/bin/env python3
"""One-shot porting dossier for a function: everything the decomp loop needs to
port a stub, in a single daemon query.

For the function at 0xADDR, prints:
  - identity: symbols.csv name/size/prototype, current owner (manual file:line,
    autogen stub, or unowned) and callers (with their owners);
  - every direct CALL with ILT thunks chased to the real target, named from
    symbols.csv, plus that target's owner (so callee-porting needs are obvious);
  - every indirect CALL: vtable-slot calls (byte offset + slot index) and
    IAT/import calls (import symbol name);
  - every referenced global (data address -> symbols.csv name, read/write);
  - jump tables (switch dispatch) detected from indirect JMPs;
  - the decompile (same output as `just ghidra-decompile`).

usage: portprep 0xADDR [--no-decompile]
"""

from __future__ import annotations

import glob
import re
import sys

from tools.ghidra import decompile_one

_MARKER_RE = re.compile(r"(?:FUNCTION|STUB|SYNTHETIC|LIBRARY): IMPERIALISM 0x([0-9a-fA-F]{6,8})")


def _load_symbols() -> dict[int, tuple[str, str]]:
  """addr -> (curated name, prototype) from config/symbols.csv."""
  table: dict[int, tuple[str, str]] = {}
  try:
    with open("config/symbols.csv", encoding="utf-8", errors="replace") as fh:
      for line in fh:
        parts = line.rstrip("\n").split("|")  # pipe-split-ok: symbols.csv is headerless
        if len(parts) >= 6:
          try:
            addr = int(parts[0], 16)
          except ValueError:
            continue
          table[addr] = (parts[1], parts[5])
  except OSError:
    pass
  return table


def _load_owners() -> dict[int, str]:
  """addr -> 'path:line' for every marker in manual source and autogen stubs."""
  owners: dict[int, str] = {}
  for pattern in ("src/game/*.cpp", "include/game/*.h", "src/autogen/stubs/*.cpp"):
    for path in glob.glob(pattern):
      try:
        with open(path, encoding="utf-8", errors="replace") as fh:
          for lineno, line in enumerate(fh, 1):
            m = _MARKER_RE.search(line)
            if m:
              owners.setdefault(int(m.group(1), 16), f"{path}:{lineno}")
      except OSError:
        continue
  return owners


def _owner_str(addr: int, owners: dict[int, str]) -> str:
  where = owners.get(addr)
  if where is None:
    return "UNOWNED"
  if "/autogen/stubs/" in where:
    return f"STUB ({where})"
  return where


def _chase_thunk(program, listing, fm, addr, depth: int = 4):
  """Follow unconditional-JMP islands (ILT thunks) to the real target address."""
  seen = []
  for _ in range(depth):
    fn = fm.getFunctionAt(addr)
    if fn is not None and fn.isThunk():
      thunked = fn.getThunkedFunction(True)
      if thunked is not None:
        seen.append(addr)
        addr = thunked.getEntryPoint()
        continue
    if fn is not None:
      return addr, seen
    ins = listing.getInstructionAt(addr)
    if ins is not None and ins.getMnemonicString().upper().startswith("JMP"):
      flows = ins.getFlows()
      if len(flows) == 1:
        seen.append(addr)
        addr = flows[0]
        continue
    return addr, seen
  return addr, seen


def run(program, argv: list[str]) -> int:
  if not argv:
    print("usage: portprep 0xADDR [--no-decompile]", file=sys.stderr)
    return 2
  want_decompile = "--no-decompile" not in argv
  addr_int = int([a for a in argv if not a.startswith("--")][0], 16)

  af = program.getAddressFactory().getDefaultAddressSpace()
  fm = program.getFunctionManager()
  listing = program.getListing()
  refmgr = program.getReferenceManager()
  symtab = program.getSymbolTable()

  entry = af.getAddress(addr_int)
  fn = fm.getFunctionContaining(entry)
  if fn is None:
    print(f"0x{addr_int:08x}: no function here")
    return 1
  entry = fn.getEntryPoint()
  entry_int = int(str(entry), 16)

  symbols = _load_symbols()
  owners = _load_owners()

  name, proto = symbols.get(entry_int, (fn.getName(), ""))
  body = fn.getBody()
  size = body.getNumAddresses()
  print("=" * 74)
  print(f"portprep 0x{entry_int:08x}  {name}")
  print(f"  size: {size}B   owner: {_owner_str(entry_int, owners)}")
  if proto:
    print(f"  symbols.csv proto: {proto}")

  # Last instruction => RET imm gives stack-arg bytes (calling-convention hint).
  last = listing.getInstructionAt(body.getMaxAddress())
  if last is None:
    it = listing.getInstructions(body, True)
    for ins in it:
      last = ins
  if last is not None and last.getMnemonicString().upper().startswith("RET"):
    print(f"  epilogue: {last}")

  # Callers.
  print("-- callers --")
  callers = []
  for ref in refmgr.getReferencesTo(entry):
    if not ref.getReferenceType().isCall() and not ref.getReferenceType().isJump():
      continue
    src = ref.getFromAddress()
    src_fn = fm.getFunctionContaining(src)
    if src_fn is None:
      callers.append(f"  {src} (thunk/loose)")
      continue
    src_entry = int(str(src_fn.getEntryPoint()), 16)
    src_name = symbols.get(src_entry, (src_fn.getName(), ""))[0]
    callers.append(f"  {src} in {src_name} (0x{src_entry:08x}) [{_owner_str(src_entry, owners)}]")
  for line in callers[:12] or ["  (none found)"]:
    print(line)
  if len(callers) > 12:
    print(f"  ... {len(callers) - 12} more")

  direct: dict[int, list[str]] = {}
  slot_calls: list[str] = []
  import_calls: list[str] = []
  reg_calls: list[str] = []
  globals_seen: dict[int, str] = {}
  jump_tables: list[str] = []

  data_min = 0x628000  # beyond .text: rdata/data/bss for this binary
  for ins in listing.getInstructions(body, True):
    mnem = ins.getMnemonicString().upper()
    text = str(ins)
    if mnem.startswith("CALL"):
      flows = ins.getFlows()
      if flows:
        tgt = flows[0]
        real, hops = _chase_thunk(program, listing, fm, tgt)
        real_int = int(str(real), 16)
        label = symbols.get(real_int, (str(fm.getFunctionAt(real) or real), ""))[0]
        via = f" via thunk 0x{int(str(tgt), 16):08x}" if hops else ""
        direct.setdefault(real_int, [label, _owner_str(real_int, owners), via, "0"])
        direct[real_int][3] = str(int(direct[real_int][3]) + 1)
      elif "[" in text:
        m = re.search(r"\[(E[A-Z]{2}) \+ (0x[0-9a-fA-F]+)\]", text)
        if m:
          off = int(m.group(2), 16)
          slot_calls.append(f"  {ins.getAddress()}  {text}   (slot 0x{off // 4:x})")
        else:
          m2 = re.search(r"\[(0x[0-9a-fA-F]+)\]", text)
          if m2:
            ptr = int(m2.group(1), 16)
            sym = symtab.getPrimarySymbol(af.getAddress(ptr))
            import_calls.append(f"  {ins.getAddress()}  {text}   -> {sym}")
          else:
            reg_calls.append(f"  {ins.getAddress()}  {text}")
      else:
        reg_calls.append(f"  {ins.getAddress()}  {text}")
    elif mnem.startswith("JMP") and "[" in text and "*" in text:
      jump_tables.append(f"  {ins.getAddress()}  {text}")
    # Globals: any reference into data space.
    for ref in ins.getReferencesFrom():
      to = ref.getToAddress()
      if not to.isMemoryAddress():
        continue
      to_int = int(str(to), 16)
      if to_int >= data_min and (ref.getReferenceType().isRead() or ref.getReferenceType().isWrite()
                                 or ref.getReferenceType().isData()):
        mode = "W" if ref.getReferenceType().isWrite() else "R"
        prev = globals_seen.get(to_int, "")
        if mode not in prev:
          globals_seen[to_int] = prev + mode

  print("-- direct calls (thunks chased) --")
  if direct:
    for tgt in sorted(direct):
      label, owner, via, count = direct[tgt]
      times = f" x{count}" if int(count) > 1 else ""
      print(f"  0x{tgt:08x}  {label}{via}{times}   [{owner}]")
  else:
    print("  (none)")
  if slot_calls:
    print("-- indirect vtable-slot calls --")
    for line in slot_calls:
      print(line)
  if import_calls:
    print("-- import (IAT) calls --")
    for line in import_calls:
      print(line)
  if reg_calls:
    print("-- register-indirect calls --")
    for line in reg_calls:
      print(line)
  if jump_tables:
    print("-- jump tables (switch dispatch) --")
    for line in jump_tables:
      print(line)

  print("-- globals referenced (consecutive runs collapsed) --")
  if globals_seen:
    run_start = None
    prev = None
    for g in sorted(globals_seen) + [None]:
      if run_start is not None and g is not None and g - prev <= 4 and g not in symbols:
        prev = g
        continue
      if run_start is not None:
        if prev - run_start >= 8:
          print(f"  0x{run_start:08x}..0x{prev:08x} [{globals_seen[run_start]}]  "
                f"(run of {(prev - run_start) // 4 + 1} dwords)")
        else:
          for a in sorted(x for x in globals_seen if run_start <= x <= prev):
            print(f"  0x{a:08x} [{globals_seen[a]}]  {symbols.get(a, ('?', ''))[0]}")
      run_start = g
      prev = g
  else:
    print("  (none)")

  if want_decompile:
    print("-- decompile --")
    decompile_one.run(program, [f"0x{entry_int:08x}"])
  return 0
