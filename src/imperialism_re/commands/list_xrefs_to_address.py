#!/usr/bin/env python3
"""
List references to one or more addresses with function/instruction context.

Usage:
  uv run impk list_xrefs_to_address <addr_hex> [addr_hex...]

Output columns:
  target_addr,from_addr,ref_type,function_addr,function_name,instruction
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import repo_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    args = ap.parse_args()

    root = repo_root()
    targets = [parse_hex(a) for a in args.targets]

    with open_program(root) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        listing = program.getListing()

        print("target_addr,from_addr,ref_type,function_addr,function_name,instruction")
        for t in targets:
            taddr = af.getAddress(f"0x{t:08x}")
            refs = rm.getReferencesTo(taddr)
            seen = set()
            for ref in refs:
                from_addr = ref.getFromAddress()
                fn = fm.getFunctionContaining(from_addr)
                fn_name = fn.getName() if fn is not None else "<no_func>"
                fn_addr = str(fn.getEntryPoint()) if fn is not None else "<no_func_addr>"
                ins = listing.getInstructionAt(from_addr)
                ins_text = str(ins) if ins is not None else "<no_inst>"
                rtype = str(ref.getReferenceType())
                key = (str(from_addr), rtype, fn_addr, fn_name, ins_text)
                if key in seen:
                    continue
                seen.add(key)
                print(
                    f"0x{t:08x},{from_addr},{rtype},{fn_addr},{fn_name},\"{ins_text}\""
                )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
