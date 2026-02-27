#!/usr/bin/env python3
"""
Dump struct layout from Ghidra datatype manager.

Usage:
  uv run impk dump_struct_layout --name TradeControl
  uv run impk dump_struct_layout --path /imperialism/classes/TradeControl
"""

from __future__ import annotations

import argparse

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program

def dump_type(dt, label: str):
    print(f"TYPE {label} size=0x{dt.getLength():x}")
    for comp in dt.getComponents():
        off = int(comp.getOffset())
        nm = comp.getFieldName() or "<anon>"
        tn = comp.getDataType().getName()
        print(f"  +0x{off:02x} {nm} : {tn}")
    print()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", action="append", default=[], help="Full datatype path, e.g. /TradeControl")
    ap.add_argument("--name", action="append", default=[], help="Datatype name to resolve in common categories")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    if not args.path and not args.name:
        print("provide --path and/or --name")
        return 1

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        dtm = program.getDataTypeManager()

        done = 0
        for p in args.path:
            dt = dtm.getDataType(p)
            if dt is None:
                print(f"MISSING {p}")
                continue
            dump_type(dt, p)
            done += 1

        common_cats = ["/", "/imperialism/classes", "/imperialism/types", "/Imperialism/classes"]
        for n in args.name:
            for cat in common_cats:
                p = f"{cat.rstrip('/')}/{n}" if cat != "/" else f"/{n}"
                dt = dtm.getDataType(p)
                if dt is None:
                    continue
                dump_type(dt, p)
                done += 1

        if done == 0:
            print("no matching datatypes found")
            return 1

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

