#!/usr/bin/env python3
"""
Move specific functions to Global namespace from CSV.

CSV columns:
  - address (required)
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    if not csv_path.exists():
        print(f"[error] missing csv: {csv_path}")
        return 1

    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    if not rows:
        print("no rows")
        return 0

    root = resolve_project_root(args.project_root)
    with open_program(root) as program:
        fm = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        global_ns = program.getGlobalNamespace()

        plans = []
        bad = 0
        for i, r in enumerate(rows, start=1):
            addr_txt = (r.get("address") or "").strip()
            if not addr_txt:
                bad += 1
                print(f"[row-fail] row={i} missing address")
                continue
            try:
                addr_i = parse_hex(addr_txt)
            except Exception as ex:
                bad += 1
                print(f"[row-fail] row={i} addr={addr_txt} err={ex}")
                continue

            fn = fm.getFunctionAt(af.getAddress(f"0x{addr_i:08x}"))
            if fn is None:
                bad += 1
                print(f"[row-fail] row={i} missing function at 0x{addr_i:08x}")
                continue

            plans.append(fn)

        print(f"[rows] total={len(rows)} planned={len(plans)} bad={bad}")
        for fn in plans[:240]:
            cur = fn.getParentNamespace()
            cur_name = cur.getName() if cur is not None else "Global"
            print(f"  {fn.getEntryPoint()} {fn.getName()} {cur_name} -> Global")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Move functions to global namespace")
        ok = skip = fail = 0
        try:
            for fn in plans:
                try:
                    if fn.getParentNamespace() == global_ns:
                        skip += 1
                        continue
                    fn.setParentNamespace(global_ns)
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {fn.getEntryPoint()} {fn.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("move functions to global namespace csv", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
