#!/usr/bin/env python3
"""
Dump compact function context for address candidates.

Usage:
  uv run impk dump_function_context [--full | --max-lines N] <addr_or_csv> [addr_or_csv...]

Inputs:
  - Hex addresses (0x004bfb20)
  - CSV files with one of columns:
      address | callee_addr | caller_addr
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import repo_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def parse_inputs(tokens: list[str]) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()

    def add(v: int):
        if v not in seen:
            seen.add(v)
            out.append(v)

    for token in tokens:
        p = Path(token)
        if p.exists() and p.suffix.lower() == ".csv":
            with p.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    raw = (
                        (row.get("address") or "").strip()
                        or (row.get("callee_addr") or "").strip()
                        or (row.get("caller_addr") or "").strip()
                    )
                    if not raw:
                        continue
                    try:
                        add(parse_hex(raw))
                    except Exception:
                        continue
            continue
        add(parse_hex(token))
    return out

def safe_get_string(program, to_addr) -> str | None:
    listing = program.getListing()
    d = listing.getDataAt(to_addr)
    if d is None:
        return None
    val = d.getValue()
    if val is None:
        return None
    s = str(val)
    if not s:
        return None
    if "??" in s:
        return None
    if len(s) > 200:
        s = s[:200] + "..."
    return s

def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 20, None)
    if not res.decompileCompleted():
        return "<decompile-failed>"
    return str(res.getDecompiledFunction().getC())

def summarize_c(c_code: str, max_lines: int) -> str:
    lines = [ln.rstrip() for ln in c_code.splitlines() if ln.strip()]
    if max_lines <= 0:
        return "\n".join(lines)
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head = lines[: max_lines - 3]
    tail = lines[-2:]
    return "\n".join(head + ["/* ... */"] + tail)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--max-lines", type=int, default=24)
    ap.add_argument("sources", nargs="+")
    args = ap.parse_args()

    root = repo_root()
    max_lines = 0 if args.full else args.max_lines

    addrs = parse_inputs(args.sources)
    if not addrs:
        print("no addresses parsed")
        return 1

    with open_program(root) as program:
        from ghidra.app.decompiler import DecompInterface

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        ifc = DecompInterface()
        ifc.openProgram(program)

        for addr_int in addrs:
            addr = af.getAddress(f"0x{addr_int:08x}")
            func = fm.getFunctionAt(addr)
            if func is None:
                print(f"\n=== 0x{addr_int:08x} ===")
                print("function: <missing>")
                continue

            called = {}
            strings = []
            ins_it = listing.getInstructions(func.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                text = str(ins)
                if text.startswith("CALL "):
                    for ref in ins.getReferencesFrom():
                        cf = fm.getFunctionAt(ref.getToAddress())
                        if cf is not None:
                            called[str(cf.getEntryPoint())] = cf.getName()
                for ref in ins.getReferencesFrom():
                    if ref.getReferenceType().isData():
                        sval = safe_get_string(program, ref.getToAddress())
                        if sval:
                            strings.append((str(ref.getToAddress()), sval))

            c_code = decompile_text(ifc, func)
            print(f"\n=== 0x{addr_int:08x} {func.getName()} ===")
            print(f"signature: {func.getSignature()}")
            if called:
                called_items = sorted(called.items(), key=lambda kv: kv[0])
                print("callees:")
                for ep, nm in called_items[:30]:
                    print(f"  - {ep} {nm}")
                if len(called_items) > 30:
                    print(f"  - ... ({len(called_items) - 30} more)")
            else:
                print("callees: <none>")

            if strings:
                uniq = []
                seen = set()
                for a, s in strings:
                    key = (a, s)
                    if key in seen:
                        continue
                    seen.add(key)
                    uniq.append((a, s))
                print("strings:")
                for a, s in uniq[:12]:
                    print(f"  - {a}: {s}")
                if len(uniq) > 12:
                    print(f"  - ... ({len(uniq) - 12} more)")
            else:
                print("strings: <none>")

            print("decomp:")
            print(summarize_c(c_code, max_lines))

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
